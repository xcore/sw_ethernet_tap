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
 * \brief   The interface between the xscope receiver and outputter core
 */
interface outputter_config {
  void set_output_packets(int enabled);
};

/**
 * \brief   A core that performs buffer management and manages the analysis tile.
 *
 * \param   c_receiver_to_control     Channel for communication with receiver.
 * \param   c_control_to_analysis     Channel for communication with analyser.
 * \param   c_outputter_to_control    Channel for communication with outputter.
 */
void analysis_control(chanend c_receiver_to_control, chanend c_control_to_analysis,
    chanend c_outputter_to_control);

/**
 * \brief   A core that receives buffers from the other tile.
 *
 * \param   c_inter_tile              Channel for inter-tile communication.
 * \param   c_receiver_to_control     Channel for communication with controller.
 */
void buffer_receiver(chanend c_inter_tile, chanend c_receiver_to_control);

/**
 * \brief   A core that performs analysis of each packet buffer received.
 *
 * \param   c_control_to_analysis     Channel for communication with controller.
 * \param   c_analysis_to_outputter   Channel for communication with outputter.
 */
void analyser(chanend c_control_to_analysis, chanend c_analysis_to_outputter);

/**
 * \brief   A core that can optionally send packets received to the host.
 *
 * \param   i_config                  Configuration interface from host.
 * \param   c_analysis_to_outputter   Channel for communication with analysis core.
 * \param   c_outputter_to_control    Channel for communication with controller.
 */
void xscope_outputter(server interface outputter_config i_config,
    chanend c_analysis_to_outputter, chanend c_outputter_to_control);

/**
 * \brief   A core that performs the checks on the stream packet rate once a 
 *          second.
 *
 * \param   i_config    The configuration interface for host control.
 */
void periodic_checks(server interface analysis_config i_config);

#endif // __ANALYSIS_TILE_H__
