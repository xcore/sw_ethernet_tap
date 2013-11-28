#ifndef __RECEIVER_TILE_H__
#define __RECEIVER_TILE_H__

/**
 * \brief   The interface between the xscope receiver and the relay control
 */
interface ethernet_tap_relay_control {
  void set_relay_open();
  void set_relay_close();
};

/**
 * \brief   The controller which manages buffers and ensures they are all sent
 *          on to the analysis tile.
 *
 * \param   c_mii1                    Channel for communication with first MII.
 * \param   c_mii2                    Channel for communication with second MII.
 * \param   c_control_to_sender       Channel for communication with sender.
 */
void receiver_control(streaming chanend c_mii1, streaming chanend c_mii2,
    streaming chanend c_control_to_sender);

/**
 * \brief   A core to send packet buffers to the analysis tile.
 *
 * \param   c_control_to_sender       Channel for communication with controller.
 * \param   c_inter_tile              Channel for inter-tile communication.
 */
void buffer_sender(streaming chanend c_control_to_sender, chanend c_inter_tile);

/**
 * \brief   A core to control the ethernet tap relay
 *
 * \param   i_relay_control           Interface for controlling the relay
 */
void relay_control(server interface ethernet_tap_relay_control i_relay_control);

#endif // __RECEIVER_TILE_H__
