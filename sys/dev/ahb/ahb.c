/*-
 * CAM SCSI device driver for the Adaptec 174X SCSI Host adapter
 *
 * Copyright (c) 1998 Justin T. Gibbs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/bus.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>

#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/cam_sim.h>
#include <cam/cam_xpt_sim.h>
#include <cam/cam_debug.h>

#include <cam/scsi/scsi_message.h>

#include <dev/eisa/eisaconf.h>

#include <dev/ahb/ahbreg.h>

#define ccb_ecb_ptr spriv_ptr0
#define ccb_ahb_ptr spriv_ptr1

#define ahb_inb(ahb, port)				\
	bus_read_1((ahb)->res, port)

#define ahb_inl(ahb, port)				\
	bus_read_4((ahb)->res, port)

#define ahb_outb(ahb, port, value)			\
	bus_write_1((ahb)->res, port, value)

#define ahb_outl(ahb, port, value)			\
	bus_write_4((ahb)->res, port, value)

static const char		*ahbmatch(eisa_id_t type);
static struct ahb_softc		*ahballoc(device_t dev, struct resource *res);
static void			 ahbfree(struct ahb_softc *ahb);
static int			 ahbreset(struct ahb_softc *ahb);
static void			 ahbmapecbs(void *arg, bus_dma_segment_t *segs,
					    int nseg, int error);
static int			 ahbxptattach(struct ahb_softc *ahb);
static void			 ahbhandleimmed(struct ahb_softc *ahb,
						u_int32_t mbox, u_int intstat);
static void			 ahbcalcresid(struct ahb_softc *ahb,
					      struct ecb *ecb, union ccb *ccb);
static __inline void		 ahbdone(struct ahb_softc *ahb, u_int32_t mbox,
					 u_int intstat);
static void			 ahbintr(void *arg);
static void			 ahbintr_locked(struct ahb_softc *ahb);
static bus_dmamap_callback_t	 ahbexecuteecb;
static void			 ahbaction(struct cam_sim *sim, union ccb *ccb);
static void			 ahbpoll(struct cam_sim *sim);

/* Our timeout handler */
static void			 ahbtimeout(void *arg);

static __inline struct ecb*	ahbecbget(struct ahb_softc *ahb);
static __inline void	 	ahbecbfree(struct ahb_softc* ahb,
					   struct ecb* ecb);
static __inline u_int32_t	ahbecbvtop(struct ahb_softc *ahb,
					   struct ecb *ecb);
static __inline struct ecb*	ahbecbptov(struct ahb_softc *ahb,
					   u_int32_t ecb_addr);
static __inline u_int32_t	ahbstatuspaddr(u_int32_t ecb_paddr);
static __inline u_int32_t	ahbsensepaddr(u_int32_t ecb_paddr);
static __inline u_int32_t	ahbsgpaddr(u_int32_t ecb_paddr);
static __inline void		ahbqueuembox(struct ahb_softc *ahb,
					     u_int32_t mboxval,
					     u_int attn_code);

static __inline struct ecb*
ahbecbget(struct ahb_softc *ahb)
{
	struct	ecb* ecb;

	if (!dumping)
		mtx_assert(&ahb->lock, MA_OWNED);
	if ((ecb = SLIST_FIRST(&ahb->free_ecbs)) != NULL)
		SLIST_REMOVE_HEAD(&ahb->free_ecbs, links);

	return (ecb);
}

static __inline void
ahbecbfree(struct ahb_softc* ahb, struct ecb* ecb)
{

	if (!dumping)
		mtx_assert(&ahb->lock, MA_OWNED);
	ecb->state = ECB_FREE;
	SLIST_INSERT_HEAD(&ahb->free_ecbs, ecb, links);
}

static __inline u_int32_t
ahbecbvtop(struct ahb_softc *ahb, struct ecb *ecb)
{
	return (ahb->ecb_physbase
	      + (u_int32_t)((caddr_t)ecb - (caddr_t)ahb->ecb_array));
}

static __inline struct ecb*
ahbecbptov(struct ahb_softc *ahb, u_int32_t ecb_addr)
{
	return (ahb->ecb_array
	      + ((struct ecb*)(uintptr_t)ecb_addr 
		- (struct ecb*)(uintptr_t)ahb->ecb_physbase));
}

static __inline u_int32_t
ahbstatuspaddr(u_int32_t ecb_paddr)
{
	return (ecb_paddr + offsetof(struct ecb, status));
}

static __inline u_int32_t
ahbsensepaddr(u_int32_t ecb_paddr)
{
	return (ecb_paddr + offsetof(struct ecb, sense));
}

static __inline u_int32_t
ahbsgpaddr(u_int32_t ecb_paddr)
{
	return (ecb_paddr + offsetof(struct ecb, sg_list));
}

static __inline void
ahbqueuembox(struct ahb_softc *ahb, u_int32_t mboxval, u_int attn_code)
{
	u_int loopmax = 300;
	while (--loopmax) {
		u_int status;

		status = ahb_inb(ahb, HOSTSTAT);
		if ((status & (HOSTSTAT_MBOX_EMPTY|HOSTSTAT_BUSY))
		   == HOSTSTAT_MBOX_EMPTY)
			break;
		DELAY(20);
	}
	if (loopmax == 0)
		panic("%s: adapter not taking commands\n",
		    device_get_nameunit(ahb->dev));

	ahb_outl(ahb, MBOXOUT0, mboxval);
	ahb_outb(ahb, ATTN, attn_code);
}

static const char *
ahbmatch(eisa_id_t type)
{                         
	switch(type & 0xfffffe00) {
		case EISA_DEVICE_ID_ADAPTEC_1740:
			return ("Adaptec 174x SCSI host adapter");
			break;
		default:
			break;
	}
	return (NULL);
} 

static int
ahbprobe(device_t dev)      
{       
	const char *desc;
	u_int32_t iobase;
	u_int32_t irq;
	u_int8_t  intdef;      
	int shared;
                
	desc = ahbmatch(eisa_get_id(dev));
	if (!desc)
	    return (ENXIO);
	device_set_desc(dev, desc);

	iobase = (eisa_get_slot(dev) * EISA_SLOT_SIZE) +
	    AHB_EISA_SLOT_OFFSET;
                        
	eisa_add_iospace(dev, iobase, AHB_EISA_IOSIZE, RESVADDR_NONE);
		
	intdef = inb(INTDEF + iobase);
	switch (intdef & 0x7) {
	case INT9:  
	    irq = 9;
	    break;
	case INT10: 
	    irq = 10;
	    break;
	case INT11:
	    irq = 11;
	    break;
	case INT12:
	    irq = 12; 
	    break;
	case INT14:
	    irq = 14;
	    break;
	case INT15:
	    irq = 15;
	    break;
	default:
	    printf("Adaptec 174X at slot %d: illegal "
		   "irq setting %d\n", eisa_get_slot(dev),
		   (intdef & 0x7));
	    irq = 0;
	    break;
	}               
	if (irq == 0)
	    return ENXIO;

	shared = (inb(INTDEF + iobase) & INTLEVEL) ?
		 EISA_TRIGGER_LEVEL : EISA_TRIGGER_EDGE;

	eisa_add_intr(dev, irq, shared);

	return 0;   
}

static int
ahbattach(device_t dev)
{
	/*
	 * find unit and check we have that many defined
	 */
	struct	    ahb_softc *ahb;
	struct	    ecb* next_ecb;
	struct	    resource *io;
	struct	    resource *irq;
	int	    rid;
	void	    *ih;

	irq = NULL;
	rid = 0;
	io = bus_alloc_resource_any(dev, SYS_RES_IOPORT, &rid, RF_ACTIVE);
	if (io == NULL) {
		device_printf(dev, "No I/O space?!\n");
		return ENOMEM;
	}

	ahb = ahballoc(dev, io);

	if (ahbreset(ahb) != 0)
		goto error_exit;

	rid = 0;
	irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid, RF_ACTIVE);
	if (irq == NULL) {
		device_printf(dev, "Can't allocate interrupt\n");
		goto error_exit;
	}

	/*
	 * Create our DMA tags.  These tags define the kinds of device
	 * accessible memory allocations and memory mappings we will 
	 * need to perform during normal operation.
	 */
	/* DMA tag for mapping buffers into device visible space. */
	if (bus_dma_tag_create(	/* parent	*/ bus_get_dma_tag(dev),
				/* alignment	*/ 1,
				/* boundary	*/ 0,
				/* lowaddr	*/ BUS_SPACE_MAXADDR_32BIT,
				/* highaddr	*/ BUS_SPACE_MAXADDR,
				/* filter	*/ NULL,
				/* filterarg	*/ NULL,
				/* maxsize	*/ DFLTPHYS,
				/* nsegments	*/ AHB_NSEG,
				/* maxsegsz	*/ BUS_SPACE_MAXSIZE_32BIT,
				/* flags	*/ BUS_DMA_ALLOCNOW,
				/* lockfunc	*/ busdma_lock_mutex,
				/* lockarg	*/ &ahb->lock,
				&ahb->buffer_dmat) != 0)
		goto error_exit;

	ahb->init_level++;

	/* DMA tag for our ccb structures and ha inquiry data */
	if (bus_dma_tag_create(	/* parent	*/ bus_get_dma_tag(dev),
				/* alignment	*/ 1,
				/* boundary	*/ 0,
				/* lowaddr	*/ BUS_SPACE_MAXADDR_32BIT,
				/* highaddr	*/ BUS_SPACE_MAXADDR,
				/* filter	*/ NULL,
				/* filterarg	*/ NULL,
				/* maxsize	*/ (AHB_NECB *
						    sizeof(struct ecb))
						    + sizeof(*ahb->ha_inq_data),
				/* nsegments	*/ 1,
				/* maxsegsz	*/ BUS_SPACE_MAXSIZE_32BIT,
				/* flags	*/ 0,
				/* lockfunc	*/ NULL,
				/* lockarg	*/ NULL,
				&ahb->ecb_dmat) != 0)
		goto error_exit;

	ahb->init_level++;

	/* Allocation for our ccbs */
	if (bus_dmamem_alloc(ahb->ecb_dmat, (void **)&ahb->ecb_array,
			     BUS_DMA_NOWAIT, &ahb->ecb_dmamap) != 0)
		goto error_exit;

	ahb->ha_inq_data = (struct ha_inquiry_data *)&ahb->ecb_array[AHB_NECB];

	ahb->init_level++;

	/* And permanently map them */
	bus_dmamap_load(ahb->ecb_dmat, ahb->ecb_dmamap,
			ahb->ecb_array, AHB_NSEG * sizeof(struct ecb),
			ahbmapecbs, ahb, /*flags*/0);

	ahb->init_level++;

	/* Allocate the buffer dmamaps for each of our ECBs */
	bzero(ahb->ecb_array, (AHB_NECB * sizeof(struct ecb))
	      + sizeof(*ahb->ha_inq_data));
	next_ecb = ahb->ecb_array;
	while (ahb->num_ecbs < AHB_NECB) {
		u_int32_t ecb_paddr;

		if (bus_dmamap_create(ahb->buffer_dmat, /*flags*/0,
				      &next_ecb->dmamap))
			break;
		callout_init_mtx(&next_ecb->timer, &ahb->lock, 0);
		ecb_paddr = ahbecbvtop(ahb, next_ecb);
		next_ecb->hecb.status_ptr = ahbstatuspaddr(ecb_paddr);
		next_ecb->hecb.sense_ptr = ahbsensepaddr(ecb_paddr);
		ahb->num_ecbs++;
		ahbecbfree(ahb, next_ecb);
		next_ecb++;
	}

	ahb->init_level++;

	/*
	 * Now that we know we own the resources we need, register
	 * our bus with the XPT.
	 */
	if (ahbxptattach(ahb))
		goto error_exit;

	/* Enable our interrupt */
	if (bus_setup_intr(dev, irq, INTR_TYPE_CAM|INTR_ENTROPY|INTR_MPSAFE,
	    NULL, ahbintr,  ahb, &ih) != 0)
		goto error_exit;

	return (0);

error_exit:
	/*
	 * The board's IRQ line will not be left enabled
	 * if we can't initialize correctly, so its safe
	 * to release the irq.
	 */
	ahbfree(ahb);
	if (irq != NULL)
		bus_release_resource(dev, SYS_RES_IRQ, 0, irq);
	bus_release_resource(dev, SYS_RES_IOPORT, 0, io);
	return (-1);
}

static struct ahb_softc *
ahballoc(device_t dev, struct resource *res)
{
	struct	ahb_softc *ahb;

	ahb = device_get_softc(dev);
	SLIST_INIT(&ahb->free_ecbs);
	LIST_INIT(&ahb->pending_ccbs);
	ahb->res = res;
	ahb->disc_permitted = ~0;
	ahb->tags_permitted = ~0;
	ahb->dev = dev;
	mtx_init(&ahb->lock, "ahb", NULL, MTX_DEF);

	return (ahb);
}

static void    
ahbfree(struct ahb_softc *ahb)
{
	switch (ahb->init_level) {
	default:
	case 4:
		bus_dmamap_unload(ahb->ecb_dmat, ahb->ecb_dmamap);
	case 3:
		bus_dmamem_free(ahb->ecb_dmat, ahb->ecb_array,
				ahb->ecb_dmamap);
	case 2:
		bus_dma_tag_destroy(ahb->ecb_dmat);
	case 1:
		bus_dma_tag_destroy(ahb->buffer_dmat);
	case 0:
		break;
	}
	mtx_destroy(&ahb->lock);
}

/*
 * reset board, If it doesn't respond, return failure
 */
static int
ahbreset(struct ahb_softc *ahb)
{
	int	wait = 1000;	/* 1 sec enough? */
	int	test;

	if ((ahb_inb(ahb, PORTADDR) & PORTADDR_ENHANCED) == 0) {
		printf("ahb_reset: Controller not in enhanced mode\n");
		return (-1);
	}

	ahb_outb(ahb, CONTROL, CNTRL_HARD_RST);
	DELAY(1000);
	ahb_outb(ahb, CONTROL, 0);
	while (--wait) {
		DELAY(1000);
		if ((ahb_inb(ahb, HOSTSTAT) & HOSTSTAT_BUSY) == 0)
			break;
	}

	if (wait == 0) {
		printf("ahbreset: No answer from aha1742 board\n");
		return (-1);
	}
	if ((test = ahb_inb(ahb, MBOXIN0)) != 0) {
		printf("ahb_reset: self test failed, val = 0x%x\n", test);
		return (-1);
	}
	while (ahb_inb(ahb, HOSTSTAT) & HOSTSTAT_INTPEND) {
		ahb_outb(ahb, CONTROL, CNTRL_CLRINT);
		DELAY(10000);
	}
	return (0);
}

static void
ahbmapecbs(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct ahb_softc* ahb;

	ahb = (struct ahb_softc*)arg;
	ahb->ecb_physbase = segs->ds_addr;
	/*
	 * Space for adapter inquiry information is on the
	 * tail of the ecb array.
	 */
	ahb->ha_inq_physbase = ahbecbvtop(ahb, &ahb->ecb_array[AHB_NECB]);
}

static int
ahbxptattach(struct ahb_softc *ahb)
{
	struct cam_devq *devq;
	struct ecb *ecb;
	u_int  i;

	mtx_lock(&ahb->lock);

	/* Remember who are we on the scsi bus */
	ahb->scsi_id = ahb_inb(ahb, SCSIDEF) & HSCSIID;

	/* Use extended translation?? */
    	ahb->extended_trans = ahb_inb(ahb, RESV1) & EXTENDED_TRANS;

	/* Fetch adapter inquiry data */
	ecb = ahbecbget(ahb);	/* Always succeeds - no outstanding commands */
	ecb->hecb.opcode = ECBOP_READ_HA_INQDATA;
	ecb->hecb.flag_word1 = FW1_SUPPRESS_URUN_ERR|FW1_ERR_STATUS_BLK_ONLY;
	ecb->hecb.data_ptr = ahb->ha_inq_physbase;
	ecb->hecb.data_len = sizeof(struct ha_inquiry_data);
	ecb->hecb.sense_ptr = 0;
	ecb->state = ECB_ACTIVE;
	
	/* Tell the adapter about this command */
	ahbqueuembox(ahb, ahbecbvtop(ahb, ecb),
		     ATTN_STARTECB|ahb->scsi_id);

	/* Poll for interrupt completion */
	for (i = 1000; ecb->state != ECB_FREE && i != 0; i--) {
		ahbintr_locked(ahb);
		DELAY(1000);
	}

	ahb->num_ecbs = MIN(ahb->num_ecbs,
			    ahb->ha_inq_data->scsi_data.spc2_flags);
	device_printf(ahb->dev,
	       "%.8s %s SCSI Adapter, FW Rev. %.4s, ID=%d, %d ECBs\n",
	       ahb->ha_inq_data->scsi_data.product,
	       (ahb->ha_inq_data->scsi_data.flags & 0x4) ? "Differential"
							 : "Single Ended",
	       ahb->ha_inq_data->scsi_data.revision,
	       ahb->scsi_id, ahb->num_ecbs);

	/* Restore sense paddr for future CCB clients */
	ecb->hecb.sense_ptr = ahbsensepaddr(ahbecbvtop(ahb, ecb));

	ahbecbfree(ahb, ecb);

	/*
	 * Create the device queue for our SIM.
	 */
	devq = cam_simq_alloc(ahb->num_ecbs);
	if (devq == NULL) {
		mtx_unlock(&ahb->lock);
		return (ENOMEM);
	}

	/*
	 * Construct our SIM entry
	 */
	ahb->sim = cam_sim_alloc(ahbaction, ahbpoll, "ahb", ahb,
	    device_get_unit(ahb->dev), &ahb->lock, 2, ahb->num_ecbs, devq);
	if (ahb->sim == NULL) {
		cam_simq_free(devq);
		mtx_unlock(&ahb->lock);
		return (ENOMEM);
	}

	if (xpt_bus_register(ahb->sim, ahb->dev, 0) != CAM_SUCCESS) {
		cam_sim_free(ahb->sim, /*free_devq*/TRUE);
		mtx_unlock(&ahb->lock);
		return (ENXIO);
	}
	
	if (xpt_create_path(&ahb->path, /*periph*/NULL,
			    cam_sim_path(ahb->sim), CAM_TARGET_WILDCARD,
			    CAM_LUN_WILDCARD) != CAM_REQ_CMP) {
		xpt_bus_deregister(cam_sim_path(ahb->sim));
		cam_sim_free(ahb->sim, /*free_devq*/TRUE);
		mtx_unlock(&ahb->lock);
		return (ENXIO);
	}
		
	/*
	 * Allow the board to generate interrupts.
	 */
	ahb_outb(ahb, INTDEF, ahb_inb(ahb, INTDEF) | INTEN);
	mtx_unlock(&ahb->lock);

	return (0);
}

static void
ahbhandleimmed(struct ahb_softc *ahb, u_int32_t mbox, u_int intstat)
{
	struct ccb_hdr *ccb_h;
	u_int target_id;

	if (ahb->immed_cmd == 0) {
		device_printf(ahb->dev, "Immediate Command complete with no "
		       " pending command\n");
		return;
	}

	target_id = intstat & INTSTAT_TARGET_MASK;

	ccb_h = LIST_FIRST(&ahb->pending_ccbs);
	while (ccb_h != NULL) {
		struct ecb *pending_ecb;
		union ccb *ccb;

		pending_ecb = (struct ecb *)ccb_h->ccb_ecb_ptr;
		ccb = pending_ecb->ccb;
		ccb_h = LIST_NEXT(ccb_h, sim_links.le);
		if (ccb->ccb_h.target_id == target_id
		 || target_id == ahb->scsi_id) {
			callout_stop(&pending_ecb->timer);
			LIST_REMOVE(&ccb->ccb_h, sim_links.le);
			if ((ccb->ccb_h.flags & CAM_DIR_MASK) != CAM_DIR_NONE)
				bus_dmamap_unload(ahb->buffer_dmat,
						  pending_ecb->dmamap);
			if (pending_ecb == ahb->immed_ecb)
				ccb->ccb_h.status =
				    CAM_CMD_TIMEOUT|CAM_RELEASE_SIMQ;
			else if (target_id == ahb->scsi_id)
				ccb->ccb_h.status = CAM_SCSI_BUS_RESET;
			else
				ccb->ccb_h.status = CAM_BDR_SENT;
			ahbecbfree(ahb, pending_ecb);
			xpt_done(ccb);
		} else if (ahb->immed_ecb != NULL) {
			/* Re-instate timeout */
			callout_reset_sbt(&pending_ecb->timer,
			    SBT_1MS * ccb->ccb_h.timeout, 0, ahbtimeout,
			    pending_ecb, 0);
		}
	}

	if (ahb->immed_ecb != NULL) {
		ahb->immed_ecb = NULL;
		device_printf(ahb->dev, "No longer in timeout\n");
	} else if (target_id == ahb->scsi_id)
		device_printf(ahb->dev, "SCSI Bus Reset Delivered\n");
	else
		device_printf(ahb->dev,
		    "Bus Device Reset Delivered to target %d\n", target_id);

	ahb->immed_cmd = 0;
}

static void
ahbcalcresid(struct ahb_softc *ahb, struct ecb *ecb, union ccb *ccb)
{
	if (ecb->status.data_overrun != 0) {
		/*
		 * Overrun Condition.  The hardware doesn't
		 * provide a meaningful byte count in this case
		 * (the residual is always 0).  Tell the XPT
		 * layer about the error.
		 */
		ccb->ccb_h.status = CAM_DATA_RUN_ERR;
	} else {
		ccb->csio.resid = ecb->status.resid_count;

		if ((ecb->hecb.flag_word1 & FW1_SG_ECB) != 0) {
			/*
			 * For S/G transfers, the adapter provides a pointer
			 * to the address in the last S/G element used and a
			 * residual for that element.  So, we need to sum up
			 * the elements that follow it in order to get a real
			 * residual number.  If we have an overrun, the residual
			 * reported will be 0 and we already know that all S/G
			 * segments have been exhausted, so we can skip this
			 * step.
			 */
			ahb_sg_t *sg;
			int	  num_sg;

			num_sg = ecb->hecb.data_len / sizeof(ahb_sg_t);

			/* Find the S/G the adapter was working on */
			for (sg = ecb->sg_list;
			     num_sg != 0 && sg->addr != ecb->status.resid_addr;
			     num_sg--, sg++)
				;

			/* Skip it */
			num_sg--;
			sg++;

			/* Sum the rest */
			for (; num_sg != 0; num_sg--, sg++)
				ccb->csio.resid += sg->len;
		}
		/* Underruns are not errors */
		ccb->ccb_h.status = CAM_REQ_CMP;
	}
}

static void
ahbprocesserror(struct ahb_softc *ahb, struct ecb *ecb, union ccb *ccb)
{
	struct hardware_ecb *hecb;
	struct ecb_status *status;

	hecb = &ecb->hecb;
	status = &ecb->status;
	switch (status->ha_status) {
	case HS_OK:
		ccb->csio.scsi_status = status->scsi_status;
		if (status->scsi_status != 0) {
			ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
			if (status->sense_stored) {
				ccb->ccb_h.status |= CAM_AUTOSNS_VALID;
				ccb->csio.sense_resid =
				    ccb->csio.sense_len - status->sense_len;
				bcopy(&ecb->sense, &ccb->csio.sense_data,
				      status->sense_len);
			}
		}
		break;
	case HS_TARGET_NOT_ASSIGNED:
		ccb->ccb_h.status = CAM_PATH_INVALID;
		break;
	case HS_SEL_TIMEOUT:
		ccb->ccb_h.status = CAM_SEL_TIMEOUT;
		break;
	case HS_DATA_RUN_ERR:
		ahbcalcresid(ahb, ecb, ccb);
		break;
	case HS_UNEXPECTED_BUSFREE:
		ccb->ccb_h.status = CAM_UNEXP_BUSFREE;
		break;
	case HS_INVALID_PHASE:
		ccb->ccb_h.status = CAM_SEQUENCE_FAIL;
		break;
	case HS_REQUEST_SENSE_FAILED:
		ccb->ccb_h.status = CAM_AUTOSENSE_FAIL;
		break;
	case HS_TAG_MSG_REJECTED:
	{
		struct ccb_trans_settings neg; 
		struct ccb_trans_settings_scsi *scsi = &neg.proto_specific.scsi;

		xpt_print_path(ccb->ccb_h.path);
		printf("refuses tagged commands.  Performing "
		       "non-tagged I/O\n");
		memset(&neg, 0, sizeof (neg));
		neg.protocol = PROTO_SCSI;
		neg.protocol_version = SCSI_REV_2;
		neg.transport = XPORT_SPI;
		neg.transport_version = 2;
		scsi->flags = CTS_SCSI_VALID_TQ;
		xpt_setup_ccb(&neg.ccb_h, ccb->ccb_h.path, /*priority*/1); 
		xpt_async(AC_TRANSFER_NEG, ccb->ccb_h.path, &neg);
		ahb->tags_permitted &= ~(0x01 << ccb->ccb_h.target_id);
		ccb->ccb_h.status = CAM_MSG_REJECT_REC;
		break;
	}
	case HS_FIRMWARE_LOAD_REQ:
	case HS_HARDWARE_ERR:
		/*
		 * Tell the system that the Adapter
		 * is no longer functional.
		 */
		ccb->ccb_h.status = CAM_NO_HBA;
		break;
	case HS_CMD_ABORTED_HOST:
	case HS_CMD_ABORTED_ADAPTER:
	case HS_ATN_TARGET_FAILED:
	case HS_SCSI_RESET_ADAPTER:
	case HS_SCSI_RESET_INCOMING:
		ccb->ccb_h.status = CAM_SCSI_BUS_RESET;
		break;
	case HS_INVALID_ECB_PARAM:
		device_printf(ahb->dev,
		    "opcode 0x%02x, flag_word1 0x%02x, flag_word2 0x%02x\n",
		    hecb->opcode, hecb->flag_word1, hecb->flag_word2);	
		ccb->ccb_h.status = CAM_SCSI_BUS_RESET;
		break;
	case HS_DUP_TCB_RECEIVED:
	case HS_INVALID_OPCODE:
	case HS_INVALID_CMD_LINK:
	case HS_PROGRAM_CKSUM_ERROR:
		panic("%s: Can't happen host status %x occurred",
		    device_get_nameunit(ahb->dev), status->ha_status);
		break;
	}
	if (ccb->ccb_h.status != CAM_REQ_CMP) {
		xpt_freeze_devq(ccb->ccb_h.path, /*count*/1);
		ccb->ccb_h.status |= CAM_DEV_QFRZN;
	}
}

static void
ahbdone(struct ahb_softc *ahb, u_int32_t mbox, u_int intstat)
{
	struct ecb *ecb;
	union ccb *ccb;

	ecb = ahbecbptov(ahb, mbox);

	if ((ecb->state & ECB_ACTIVE) == 0)
		panic("ecb not active");

	ccb = ecb->ccb;

	if (ccb != NULL) {
		callout_stop(&ecb->timer);
		LIST_REMOVE(&ccb->ccb_h, sim_links.le);

		if ((ccb->ccb_h.flags & CAM_DIR_MASK) != CAM_DIR_NONE) {
			bus_dmasync_op_t op;

			if ((ccb->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN)
				op = BUS_DMASYNC_POSTREAD;
			else
				op = BUS_DMASYNC_POSTWRITE;
			bus_dmamap_sync(ahb->buffer_dmat, ecb->dmamap, op);
			bus_dmamap_unload(ahb->buffer_dmat, ecb->dmamap);
		}

		if ((intstat & INTSTAT_MASK) == INTSTAT_ECB_OK) {
			ccb->ccb_h.status = CAM_REQ_CMP;
			ccb->csio.resid = 0;
		} else {
			ahbprocesserror(ahb, ecb, ccb);
		}
		ahbecbfree(ahb, ecb);
		xpt_done(ccb);
	} else {
		/* Non CCB Command */
		if ((intstat & INTSTAT_MASK) != INTSTAT_ECB_OK) {
			device_printf(ahb->dev, "Command 0%x Failed %x:%x:%x\n",
			       ecb->hecb.opcode,
			       *((u_int16_t*)&ecb->status),
			       ecb->status.ha_status, ecb->status.resid_count);
		}
		/* Client owns this ECB and will release it. */
	}
}

/*
 * Catch an interrupt from the adaptor
 */
static void
ahbintr(void *arg)
{
	struct	  ahb_softc *ahb;

	ahb = arg;
	mtx_lock(&ahb->lock);
	ahbintr_locked(ahb);
	mtx_unlock(&ahb->lock);
}

static void
ahbintr_locked(struct ahb_softc *ahb)
{
	u_int	  intstat;
	u_int32_t mbox;

	while (ahb_inb(ahb, HOSTSTAT) & HOSTSTAT_INTPEND) {
		/*
		 * Fetch information about this interrupt.
		 */
		intstat = ahb_inb(ahb, INTSTAT);
		mbox = ahb_inl(ahb, MBOXIN0);

		/*
		 * Reset interrupt latch.
		 */
		ahb_outb(ahb, CONTROL, CNTRL_CLRINT);

		/*
		 * Process the completed operation
		 */
		switch (intstat & INTSTAT_MASK) {
		case INTSTAT_ECB_OK:
		case INTSTAT_ECB_CMPWRETRY:
		case INTSTAT_ECB_CMPWERR:
			ahbdone(ahb, mbox, intstat);
			break;
		case INTSTAT_AEN_OCCURED:
			if ((intstat & INTSTAT_TARGET_MASK) == ahb->scsi_id) {
				/* Bus Reset */
				xpt_print_path(ahb->path);
				switch (mbox) {
				case HS_SCSI_RESET_ADAPTER:
					printf("Host Adapter Initiated "
					       "Bus Reset occurred\n");
					break;
				case HS_SCSI_RESET_INCOMING:
					printf("Bus Reset Initiated "
					       "by another device occurred\n");
					break;
				}
				/* Notify the XPT */
				xpt_async(AC_BUS_RESET, ahb->path, NULL);
				break;
			}
			printf("Unsupported initiator selection AEN occurred\n");
			break;
		case INTSTAT_IMMED_OK:
		case INTSTAT_IMMED_ERR:
			ahbhandleimmed(ahb, mbox, intstat);
			break;
		case INTSTAT_HW_ERR:
			panic("Unrecoverable hardware Error Occurred\n");
		}
	}
}

static void
ahbexecuteecb(void *arg, bus_dma_segment_t *dm_segs, int nseg, int error)
{
	struct	  ecb *ecb;
	union	  ccb *ccb;
	struct	  ahb_softc *ahb;
	u_int32_t ecb_paddr;

	ecb = (struct ecb *)arg;
	ccb = ecb->ccb;
	ahb = (struct ahb_softc *)ccb->ccb_h.ccb_ahb_ptr;
	mtx_assert(&ahb->lock, MA_OWNED);

	if (error != 0) {
		if (error != EFBIG)
			device_printf(ahb->dev,
			    "Unexepected error 0x%x returned from "
			    "bus_dmamap_load\n", error);
		if (ccb->ccb_h.status == CAM_REQ_INPROG) {
			xpt_freeze_devq(ccb->ccb_h.path, /*count*/1);
			ccb->ccb_h.status = CAM_REQ_TOO_BIG|CAM_DEV_QFRZN;
		}
		ahbecbfree(ahb, ecb);
		xpt_done(ccb);
		return;
	}
		
	ecb_paddr = ahbecbvtop(ahb, ecb);

	if (nseg != 0) {
		ahb_sg_t *sg;
		bus_dma_segment_t *end_seg;
		bus_dmasync_op_t op;

		end_seg = dm_segs + nseg;

		/* Copy the segments into our SG list */
		sg = ecb->sg_list;
		while (dm_segs < end_seg) {
			sg->addr = dm_segs->ds_addr;
			sg->len = dm_segs->ds_len;
			sg++;
			dm_segs++;
		}

		if (nseg > 1) {
			ecb->hecb.flag_word1 |= FW1_SG_ECB;
			ecb->hecb.data_ptr = ahbsgpaddr(ecb_paddr);
			ecb->hecb.data_len = sizeof(ahb_sg_t) * nseg;
		} else {
			ecb->hecb.data_ptr = ecb->sg_list->addr;
			ecb->hecb.data_len = ecb->sg_list->len;
		}

		if ((ccb->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
/*			ecb->hecb.flag_word2 |= FW2_DATA_DIR_IN; */
			op = BUS_DMASYNC_PREREAD;
		} else {
			op = BUS_DMASYNC_PREWRITE;
		}
		/* ecb->hecb.flag_word2 |= FW2_CHECK_DATA_DIR; */

		bus_dmamap_sync(ahb->buffer_dmat, ecb->dmamap, op);

	} else {
		ecb->hecb.data_ptr = 0;
		ecb->hecb.data_len = 0;
	}

	/*
	 * Last time we need to check if this CCB needs to
	 * be aborted.
	 */
	if (ccb->ccb_h.status != CAM_REQ_INPROG) {
		if (nseg != 0)
			bus_dmamap_unload(ahb->buffer_dmat, ecb->dmamap);
		ahbecbfree(ahb, ecb);
		xpt_done(ccb);
		return;
	}
		
	ecb->state = ECB_ACTIVE;
	ccb->ccb_h.status |= CAM_SIM_QUEUED;
	LIST_INSERT_HEAD(&ahb->pending_ccbs, &ccb->ccb_h, sim_links.le);

	/* Tell the adapter about this command */
	ahbqueuembox(ahb, ecb_paddr, ATTN_STARTECB|ccb->ccb_h.target_id);

	callout_reset_sbt(&ecb->timer, SBT_1MS * ccb->ccb_h.timeout, 0,
	    ahbtimeout, ecb, 0);
}

static void
ahbaction(struct cam_sim *sim, union ccb *ccb)
{
	struct	ahb_softc *ahb;

	CAM_DEBUG(ccb->ccb_h.path, CAM_DEBUG_TRACE, ("ahbaction\n"));
	
	ahb = (struct ahb_softc *)cam_sim_softc(sim);
	mtx_assert(&ahb->lock, MA_OWNED);
	
	switch (ccb->ccb_h.func_code) {
	/* Common cases first */
	case XPT_SCSI_IO:	/* Execute the requested I/O operation */
	{
		struct ecb *ecb;
		struct hardware_ecb *hecb;
		int error;

		/*
		 * get an ecb to use.
		 */
		if ((ecb = ahbecbget(ahb)) == NULL) {
			/* Should never occur */
			panic("Failed to get an ecb");
		}

		/*
		 * So we can find the ECB when an abort is requested
		 */
		ecb->ccb = ccb;
		ccb->ccb_h.ccb_ecb_ptr = ecb;
		ccb->ccb_h.ccb_ahb_ptr = ahb;

		/*
		 * Put all the arguments for the xfer in the ecb
		 */
		hecb = &ecb->hecb;
		hecb->opcode = ECBOP_INITIATOR_SCSI_CMD;
		hecb->flag_word1 = FW1_AUTO_REQUEST_SENSE
				 | FW1_ERR_STATUS_BLK_ONLY;
		hecb->flag_word2 = ccb->ccb_h.target_lun
				 | FW2_NO_RETRY_ON_BUSY;
		if ((ccb->ccb_h.flags & CAM_TAG_ACTION_VALID) != 0) {
			hecb->flag_word2 |= FW2_TAG_ENB
					 | ((ccb->csio.tag_action & 0x3)
					    << FW2_TAG_TYPE_SHIFT);
		}
		if ((ccb->ccb_h.flags & CAM_DIS_DISCONNECT) != 0)
			hecb->flag_word2 |= FW2_DISABLE_DISC;
		hecb->sense_len = ccb->csio.sense_len;
		hecb->cdb_len = ccb->csio.cdb_len;
		if ((ccb->ccb_h.flags & CAM_CDB_POINTER) != 0) {
			if ((ccb->ccb_h.flags & CAM_CDB_PHYS) == 0) {
				bcopy(ccb->csio.cdb_io.cdb_ptr,
				      hecb->cdb, hecb->cdb_len);
			} else {
				/* I guess I could map it in... */
				ccb->ccb_h.status = CAM_REQ_INVALID;
				ahbecbfree(ahb, ecb);
				xpt_done(ccb);
				return;
			}
		} else {
			bcopy(ccb->csio.cdb_io.cdb_bytes,
			      hecb->cdb, hecb->cdb_len);
		}

		error = bus_dmamap_load_ccb(
		    ahb->buffer_dmat,
		    ecb->dmamap,
		    ccb,
		    ahbexecuteecb,
		    ecb, /*flags*/0);
		if (error == EINPROGRESS) {
			/*
			 * So as to maintain ordering, freeze the controller
			 * queue until our mapping is returned.
			 */
			xpt_freeze_simq(ahb->sim, 1);
			ccb->ccb_h.status |= CAM_RELEASE_SIMQ;
		}
		break;
	}
	case XPT_EN_LUN:		/* Enable LUN as a target */
	case XPT_TARGET_IO:		/* Execute target I/O request */
	case XPT_ACCEPT_TARGET_IO:	/* Accept Host Target Mode CDB */
	case XPT_CONT_TARGET_IO:	/* Continue Host Target I/O Connection*/
	case XPT_ABORT:			/* Abort the specified CCB */
		/* XXX Implement */
		ccb->ccb_h.status = CAM_REQ_INVALID;
		xpt_done(ccb);
		break;
	case XPT_SET_TRAN_SETTINGS:
	{
		ccb->ccb_h.status = CAM_FUNC_NOTAVAIL;
		xpt_done(ccb);
		break;
	}
	case XPT_GET_TRAN_SETTINGS:
	/* Get default/user set transfer settings for the target */
	{
		struct	ccb_trans_settings *cts = &ccb->cts;
		u_int	target_mask = 0x01 << ccb->ccb_h.target_id;
		struct ccb_trans_settings_scsi *scsi =
		    &cts->proto_specific.scsi;
		struct ccb_trans_settings_spi *spi =
		    &cts->xport_specific.spi;

		if (cts->type == CTS_TYPE_USER_SETTINGS) {
			cts->protocol = PROTO_SCSI;
			cts->protocol_version = SCSI_REV_2;
			cts->transport = XPORT_SPI;
			cts->transport_version = 2;

			scsi->flags &= ~CTS_SCSI_FLAGS_TAG_ENB;
			spi->flags &= ~CTS_SPI_FLAGS_DISC_ENB;
			if ((ahb->disc_permitted & target_mask) != 0)
				spi->flags |= CTS_SPI_FLAGS_DISC_ENB;
			if ((ahb->tags_permitted & target_mask) != 0)
				scsi->flags |= CTS_SCSI_FLAGS_TAG_ENB;
			spi->bus_width = MSG_EXT_WDTR_BUS_8_BIT;
			spi->sync_period = 25; /* 10MHz */

			if (spi->sync_period != 0)
				spi->sync_offset = 15;

			spi->valid = CTS_SPI_VALID_SYNC_RATE
				   | CTS_SPI_VALID_SYNC_OFFSET
				   | CTS_SPI_VALID_BUS_WIDTH
				   | CTS_SPI_VALID_DISC;
			scsi->valid = CTS_SCSI_VALID_TQ;
			ccb->ccb_h.status = CAM_REQ_CMP;
		} else {
			ccb->ccb_h.status = CAM_FUNC_NOTAVAIL;
		}
		xpt_done(ccb);
		break;
	}
	case XPT_RESET_DEV:	/* Bus Device Reset the specified SCSI device */
	{
		int i;

		ahb->immed_cmd = IMMED_RESET;
		ahbqueuembox(ahb, IMMED_RESET, ATTN_IMMED|ccb->ccb_h.target_id);
		/* Poll for interrupt completion */
		for (i = 1000; ahb->immed_cmd != 0 && i != 0; i--) {
			DELAY(1000);
			ahbintr_locked(cam_sim_softc(sim));
		}
		break;
	}
	case XPT_CALC_GEOMETRY:
	{
		cam_calc_geometry(&ccb->ccg, ahb->extended_trans); 
		xpt_done(ccb);
		break;
	}
	case XPT_RESET_BUS:		/* Reset the specified SCSI bus */
	{
		int i;

		ahb->immed_cmd = IMMED_RESET;
		ahbqueuembox(ahb, IMMED_RESET, ATTN_IMMED|ahb->scsi_id);
		/* Poll for interrupt completion */
		for (i = 1000; ahb->immed_cmd != 0 && i != 0; i--)
			DELAY(1000);
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		break;
	}
	case XPT_TERM_IO:		/* Terminate the I/O process */
		/* XXX Implement */
		ccb->ccb_h.status = CAM_REQ_INVALID;
		xpt_done(ccb);
		break;
	case XPT_PATH_INQ:		/* Path routing inquiry */
	{
		struct ccb_pathinq *cpi = &ccb->cpi;
		
		cpi->version_num = 1; /* XXX??? */
		cpi->hba_inquiry = PI_SDTR_ABLE|PI_TAG_ABLE;
		cpi->target_sprt = 0;
		cpi->hba_misc = 0;
		cpi->hba_eng_cnt = 0;
		cpi->max_target = 7;
		cpi->max_lun = 7;
		cpi->initiator_id = ahb->scsi_id;
		cpi->bus_id = cam_sim_bus(sim);
		cpi->base_transfer_speed = 3300;
		strlcpy(cpi->sim_vid, "FreeBSD", SIM_IDLEN);
		strlcpy(cpi->hba_vid, "Adaptec", HBA_IDLEN);
		strlcpy(cpi->dev_name, cam_sim_name(sim), DEV_IDLEN);
		cpi->unit_number = cam_sim_unit(sim);
		cpi->transport = XPORT_SPI;
		cpi->transport_version = 2;
		cpi->protocol = PROTO_SCSI;
		cpi->protocol_version = SCSI_REV_2;
		cpi->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		break;
	}
#if 0
	/* Need these??? */
        case XPT_IMMED_NOTIFY:		/* Notify Host Target driver of event */
        case XPT_NOTIFY_ACK:		/* Acknowledgement of event */
#endif
	default:
		ccb->ccb_h.status = CAM_REQ_INVALID;
		xpt_done(ccb);
		break;
	}
}

static void
ahbpoll(struct cam_sim *sim)
{
	ahbintr(cam_sim_softc(sim));
}

static void
ahbtimeout(void *arg)
{
	struct ecb	 *ecb;
	union  ccb	 *ccb;
	struct ahb_softc *ahb;

	ecb = (struct ecb *)arg;
	ccb = ecb->ccb;
	ahb = (struct ahb_softc *)ccb->ccb_h.ccb_ahb_ptr;
	mtx_assert(&ahb->lock, MA_OWNED);
	xpt_print_path(ccb->ccb_h.path);
	printf("ECB %p - timed out\n", (void *)ecb);

	if ((ecb->state & ECB_ACTIVE) == 0) {
		xpt_print_path(ccb->ccb_h.path);
		printf("ECB %p - timed out ECB already completed\n",
		       (void *)ecb);
		return;
	}
	/*
	 * In order to simplify the recovery process, we ask the XPT
	 * layer to halt the queue of new transactions and we traverse
	 * the list of pending CCBs and remove their timeouts. This
	 * means that the driver attempts to clear only one error
	 * condition at a time.  In general, timeouts that occur
	 * close together are related anyway, so there is no benefit
	 * in attempting to handle errors in parallel.  Timeouts will
	 * be reinstated when the recovery process ends.
	 */
	if ((ecb->state & ECB_DEVICE_RESET) == 0) {
		struct ccb_hdr *ccb_h;

		if ((ecb->state & ECB_RELEASE_SIMQ) == 0) {
			xpt_freeze_simq(ahb->sim, /*count*/1);
			ecb->state |= ECB_RELEASE_SIMQ;
		}

		LIST_FOREACH(ccb_h, &ahb->pending_ccbs, sim_links.le) {
			struct ecb *pending_ecb;

			pending_ecb = (struct ecb *)ccb_h->ccb_ecb_ptr;
			callout_stop(&pending_ecb->timer);
		}

		/* Store for our interrupt handler */
		ahb->immed_ecb = ecb;

		/*    
		 * Send a Bus Device Reset message:
		 * The target that is holding up the bus may not
		 * be the same as the one that triggered this timeout
		 * (different commands have different timeout lengths),
		 * but we have no way of determining this from our
		 * timeout handler.  Our strategy here is to queue a
		 * BDR message to the target of the timed out command.
		 * If this fails, we'll get another timeout 2 seconds
		 * later which will attempt a bus reset.
		 */
		xpt_print_path(ccb->ccb_h.path);
		printf("Queuing BDR\n");
		ecb->state |= ECB_DEVICE_RESET;
		callout_reset(&ecb->timer, 2 * hz, ahbtimeout, ecb);

		ahb->immed_cmd = IMMED_RESET;
		ahbqueuembox(ahb, IMMED_RESET, ATTN_IMMED|ccb->ccb_h.target_id);
	} else if ((ecb->state & ECB_SCSIBUS_RESET) != 0) {
		/*
		 * Try a SCSI bus reset.  We do this only if we
		 * have already attempted to clear the condition with a BDR.
		 */
		xpt_print_path(ccb->ccb_h.path);
		printf("Attempting SCSI Bus reset\n");
		ecb->state |= ECB_SCSIBUS_RESET;
		callout_reset(&ecb->timer, 2 * hz, ahbtimeout, ecb);
		ahb->immed_cmd = IMMED_RESET;
		ahbqueuembox(ahb, IMMED_RESET, ATTN_IMMED|ahb->scsi_id);
	} else {
		/* Bring out the hammer... */
		ahbreset(ahb);

		/* Simulate the reset complete interrupt */
		ahbhandleimmed(ahb, 0, ahb->scsi_id|INTSTAT_IMMED_OK);
	}
}

static device_method_t ahb_eisa_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		ahbprobe),
	DEVMETHOD(device_attach,	ahbattach),

	{ 0, 0 }
};

static driver_t ahb_eisa_driver = {
	"ahb",
	ahb_eisa_methods,
	sizeof(struct ahb_softc),
};

static devclass_t ahb_devclass;

DRIVER_MODULE(ahb, eisa, ahb_eisa_driver, ahb_devclass, 0, 0);
MODULE_DEPEND(ahb, eisa, 1, 1, 1);
MODULE_DEPEND(ahb, cam, 1, 1, 1);
