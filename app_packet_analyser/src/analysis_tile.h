#ifndef __ANALYSIS_TILE_H__
#define __ANALYSIS_TILE_H__

/**
 * \brief   A core that performs buffer management and manages the analysis tile.
 *
 * \param   c_receiver_to_control     Channel for communication with receiver.
 * \param   c_control_to_analysis     Channel for communication with analyser.
 */
void analysis_control(streaming chanend c_receiver_to_control,
                      streaming chanend c_control_to_analysis);

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
 */
void analyser(streaming chanend c_control_to_analysis);

/**
 * \brief   A core that performs the checks on the stream packet rate once a 
 *          second.
 */
void periodic_checks();

#endif // __ANALYSIS_TILE_H__
