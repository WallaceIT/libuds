#!/usr/bin/env python3

import can
import isotp
import udsoncan
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.client import Client
from udsoncan.exceptions import *
from udsoncan.services import *


# Refer to isotp documentation for full details about parameters
isotp_params = {
   'stmin' : 20,                          # Will request the sender to wait 32ms between consecutive frame. 0-127ms or 100-900ns with values from 0xF1-0xF9
   'blocksize' : 0,                       # Request the sender to send 8 consecutives frames before sending a new flow control message
   'wftmax' : 10,                         # Number of wait frame allowed before triggering an error
   'tx_padding' : 0xFF,                   # Will pad all transmitted CAN messages with byte 0x00.
   'rx_flowcontrol_timeout' : 1000,       # Triggers a timeout if a flow control is awaited for more than 1000 milliseconds
   'rx_consecutive_frame_timeout' : 1000, # Triggers a timeout if a consecutive frame is awaited for more than 1000 milliseconds
   'squash_stmin_requirement' : False,    # When sending, respect the stmin requirement of the receiver. If set to True, go as fast as possible.
}

def myalgo(level, seed, params):
    output_key = bytearray(seed)
    xorkey = bytearray(params['xorkey'])
    for i in range(len(seed)):
        output_key[i] = seed[i] ^ xorkey[i%len(xorkey)]
    return bytes(output_key)

config = dict(udsoncan.configs.default_client_config)
config['data_identifiers'] = {
   0xF190 : udsoncan.AsciiCodec(17)
}
config['security_algo'] = myalgo
config['security_algo_params'] = dict(xorkey=b'\x12\x34\x56\x78')

bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
tp_addr = isotp.Address(isotp.AddressingMode.Normal_29bits, txid=0x18DA0102, rxid=0x18DA0201)
stack = isotp.CanStack(bus=bus, address=tp_addr, params=isotp_params)
conn = PythonIsoTpConnection(stack)
with Client(conn, config=config) as client:
    try:
        client.change_session(DiagnosticSessionControl.Session.extendedDiagnosticSession)

        client.unlock_security_access(1)

        res = client.read_data_by_identifier(udsoncan.DataIdentifier.VIN)
        client.write_data_by_identifier(udsoncan.DataIdentifier.VIN, '_ABCDEF0123456789')
        print('Vehicle Identification Number successfully changed.')

        client.change_session(DiagnosticSessionControl.Session.programmingSession)

        client.unlock_security_access(1)

        mem = udsoncan.MemoryLocation(address=0x00000008, memorysize=8, address_format=32, memorysize_format=32)
        res = client.read_memory_by_address(mem)

        mem = udsoncan.MemoryLocation(address=0x00000008, memorysize=(512 * 1024), address_format=32, memorysize_format=32)

        # Send file
        data_left = (4 * 1024)
        res = client.replace_file('/tmp/test', filesize=data_left)

        max_block_len = (res.service_data.max_length - 2)
        counter = 1
        while data_left > 0:
            num_bytes = min(data_left, max_block_len)
            res = client.transfer_data(sequence_number=counter, data=bytes(bytearray(num_bytes)))
            counter = (counter + 1) & 0xFF
            data_left -= num_bytes
        
        res = client.request_transfer_exit()

        # Receive file
        data_left = (4 * 1024)
        res = client.read_file('/tmp/test')

        max_block_len = (res.service_data.max_length - 2)
        data_left = res.service_data.filesize.compressed
        counter = 1
        with open('data.bin', 'wb') as f:
            while data_left > 0:
                res = client.transfer_data(sequence_number=counter)
                counter = (counter + 1) & 0xFF
                f.write(res.service_data.parameter_records)
                data_left -= len(res.service_data.parameter_records)

        res = client.request_transfer_exit()

    except NegativeResponseException as e:
        print('Server refused our request for service %s with code "%s" (0x%02x)' % (e.response.service.get_name(), e.response.code_name, e.response.code))
    except (InvalidResponseException, UnexpectedResponseException) as e:
        print('Server sent an invalid payload : %s' % e.response.original_payload)