#ifndef __ANALYSIS_TILE_H__
#define __ANALYSIS_TILE_H__

/**
 * \brief   The interface between the xscope receiver and checker core
 */
interface analysis_config {
  void set_expect_oversubscribed(int oversubscribed);
  void set_debug(int debug);
};

/**
 * \brief   A core that performs buffer management and manages the analysis tile.
 *
 * \param   c_receiver_to_control     Channel for communication with receiver.
 * \param   c_control_to_analysis     Channel for communication with analyser.
 * \param   c_outputter_to_control    Channel for communication with outputter.
 */
void analysis_control(streaming chanend c_receiver_to_control, streaming chanend c_control_to_analysis);

/**
 * \brief   A core that receives buffers from the other tile.
 *
 * \param   c_inter_tile              Channel for inter-tile communication.
 * \param   c_receiver_to_control     Channel for communication with controller.
 */
void buffer_receiver(chanend c_inter_tile, streaming chanend c_receiver_to_control);

/**
 * \brief   A core that performs analysis of each packet buffer received.
 *
 * \param   c_control_to_analysis     Channel for communication with controller.
 * \param   c_analysis_to_outputter   Channel for communication with outputter.
 */
void analyser(streaming chanend c_control_to_analysis);

/**
 * \brief   A core that performs the checks on the stream packet rate once a 
 *          second.
 *
 * \param   i_config    The configuration interface for host control.
 */
void periodic_checks(server interface analysis_config i_config);

#endif // __ANALYSIS_TILE_H__
