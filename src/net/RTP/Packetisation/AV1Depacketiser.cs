//-----------------------------------------------------------------------------
// Filename: AV1Depacketiser.cs
//
// Description: Implements depacketizer of AV1 OBUs from RTP packets.
// The implementation follows the AV1 RTP specification.
// The main focus is on handling aggregated OBUs and fragmented OBUs.
//
// See "RTP Payload Format for AV1" https://aomediacodec.github.io/av1-rtp-spec/
//
// Author(s):
// Auto-generated based on AV1 RTP specification.
//
// History:
// 05 Dec 2025    Created.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SIPSorcery.net.RTP.Packetisation
{
    /// <summary>
    /// Implements depacketizer of AV1 OBUs from RTP packets.
    /// The implementation follows the AV1 RTP specification.
    /// </summary>
    /// <remarks>
    /// AV1 RTP Aggregation Header Structure:
    /// 
    ///  0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+
    /// |Z|Y| W |N|-|-|-|
    /// +-+-+-+-+-+-+-+-+
    /// 
    /// Z: First OBU element is continuation of previous packet's fragment
    /// Y: Last OBU element continues in next packet
    /// W: Number of OBU elements in packet (0 = each has length field, else last has no length)
    /// N: New coded video sequence flag
    /// </remarks>
    public class AV1Depacketiser
    {
        // Buffer for assembling fragmented OBUs
        private uint _previousTimestamp = 0;
        private List<KeyValuePair<int, byte[]>> _temporaryRtpPayloads = new List<KeyValuePair<int, byte[]>>();
        private MemoryStream _fragmentBuffer = new MemoryStream();
        //private bool _fragmentInProgress = false;

        /// <summary>
        /// Processes an RTP payload and returns the reassembled OBUs as a memory stream.
        /// OBUs are concatenated with size fields in low overhead bitstream format.
        /// </summary>
        /// <param name="rtpPayload">The RTP payload bytes.</param>
        /// <param name="seqNum">RTP sequence number.</param>
        /// <param name="timestamp">RTP timestamp.</param>
        /// <param name="markbit">RTP marker bit (1 = end of frame).</param>
        /// <param name="isKeyFrame">Output: true if this frame contains a sequence header.</param>
        /// <returns>Memory stream with OBUs, or null if frame is incomplete.</returns>
        public virtual MemoryStream ProcessRTPPayload(byte[] rtpPayload, ushort seqNum, uint timestamp, int markbit, out bool isKeyFrame)
        {
            List<byte[]> obuList = ProcessRTPPayloadAsObus(rtpPayload, seqNum, timestamp, markbit, out isKeyFrame);

            if (obuList != null && obuList.Count > 0)
            {
                // Calculate total buffer size
                long totalBufferSize = 0;
                foreach (var obu in obuList)
                {
                    if (obu.Length > 0)
                    {
                        // OBU with size field (leb128)
                        totalBufferSize += AV1Packetiser.GetLeb128Size(obu.Length) + obu.Length;
                    }
                }

                // Merge OBUs in low overhead format
                MemoryStream data = new MemoryStream(new byte[totalBufferSize]);
                foreach (var obu in obuList)
                {
                    if (obu.Length > 0)
                    {
                        // Add size field and set obu_has_size_field bit
                        byte[] obuWithSize = CreateObuWithSizeField(obu);
                        data.Write(obuWithSize, 0, obuWithSize.Length);
                    }
                }

                return data;
            }

            return null;
        }

        /// <summary>
        /// Processes an RTP payload and returns the list of OBUs.
        /// </summary>
        /// <param name="rtpPayload">The RTP payload bytes.</param>
        /// <param name="seqNum">RTP sequence number.</param>
        /// <param name="timestamp">RTP timestamp.</param>
        /// <param name="markbit">RTP marker bit (1 = end of frame).</param>
        /// <param name="isKeyFrame">Output: true if this frame contains a sequence header.</param>
        /// <returns>List of OBUs, or null if frame is incomplete.</returns>
        public virtual List<byte[]> ProcessRTPPayloadAsObus(byte[] rtpPayload, ushort seqNum, uint timestamp, int markbit, out bool isKeyFrame)
        {
            return ProcessAV1Payload(rtpPayload, seqNum, timestamp, markbit, out isKeyFrame);
        }

        /// <summary>
        /// Processes an AV1 RTP payload.
        /// </summary>
        protected virtual List<byte[]> ProcessAV1Payload(byte[] rtpPayload, ushort seqNum, uint timestamp, int markbit, out bool isKeyFrame)
        {
            if (_previousTimestamp != timestamp && _previousTimestamp > 0)
            {
                _temporaryRtpPayloads.Clear();
                _fragmentBuffer.SetLength(0);
                //_fragmentInProgress = false;
                _previousTimestamp = 0;
            }

            // Add to the list of payloads for the current frame
            _temporaryRtpPayloads.Add(new KeyValuePair<int, byte[]>(seqNum, rtpPayload));

            if (markbit == 1)
            {
                // Reorder to prevent UDP incorrect packet order
                if (_temporaryRtpPayloads.Count > 1)
                {
                    _temporaryRtpPayloads.Sort((a, b) =>
                    {
                        // Detect wraparound of sequence to sort packets correctly
                        return (Math.Abs(b.Key - a.Key) > (0xFFFF - 2000)) ? -a.Key.CompareTo(b.Key) : a.Key.CompareTo(b.Key);
                    });
                }

                // Process the list of RTP packets
                List<byte[]> obuList = ProcessAV1PayloadFrame(_temporaryRtpPayloads, out isKeyFrame);
                _temporaryRtpPayloads.Clear();
                _fragmentBuffer.SetLength(0);
                //_fragmentInProgress = false;
                _previousTimestamp = 0;

                return obuList;
            }
            else
            {
                isKeyFrame = false;
                _previousTimestamp = timestamp;
                return null; // Frame incomplete
            }
        }

        /// <summary>
        /// Processes a complete frame consisting of multiple RTP packets.
        /// </summary>
        protected virtual List<byte[]> ProcessAV1PayloadFrame(List<KeyValuePair<int, byte[]>> rtpPayloads, out bool isKeyFrame)
        {
            List<byte[]> obuList = new List<byte[]>();
            MemoryStream fragmentBuffer = new MemoryStream();
            bool fragmentInProgress = false;

            foreach (var payload in rtpPayloads)
            {
                var obus = ExtractObusFromRtpPayload(payload.Value, fragmentBuffer, ref fragmentInProgress);
                if (obus != null)
                {
                    obuList.AddRange(obus);
                }
            }

            // Check if we have a complete fragment at the end
            if (fragmentInProgress && fragmentBuffer.Length > 0)
            {
                // Incomplete fragment - data loss
                fragmentBuffer.SetLength(0);
            }

            isKeyFrame = CheckKeyFrame(obuList);
            return obuList;
        }

        /// <summary>
        /// Extracts OBUs from an RTP payload.
        /// </summary>
        private List<byte[]> ExtractObusFromRtpPayload(byte[] rtpPayload, MemoryStream fragmentBuffer, ref bool fragmentInProgress)
        {
            if (rtpPayload == null || rtpPayload.Length < 2)
            {
                return null;
            }

            List<byte[]> obuList = new List<byte[]>();

            // Parse aggregation header
            byte aggHeader = rtpPayload[0];
            bool zBit = (aggHeader & 0x80) != 0; // Continuation from previous packet
            bool yBit = (aggHeader & 0x40) != 0; // Continues in next packet
            int wField = (aggHeader >> 4) & 0x03; // OBU count
            bool nBit = (aggHeader & 0x08) != 0; // New coded video sequence

            int position = 1; // Skip aggregation header

            // Determine how many OBU elements to expect
            int obuElementCount = wField > 0 ? wField : -1; // -1 means use length fields for all

            int elementIndex = 0;

            while (position < rtpPayload.Length)
            {
                long obuSize;
                bool hasLengthField;

                if (wField == 0)
                {
                    // All elements have length fields
                    hasLengthField = true;
                }
                else
                {
                    // Last element doesn't have length field
                    hasLengthField = (elementIndex < wField - 1) || (wField == 0);
                }

                if (hasLengthField && wField > 0 && elementIndex == wField - 1)
                {
                    hasLengthField = false;
                }

                if (hasLengthField)
                {
                    int bytesRead = AV1Packetiser.ReadLeb128(rtpPayload, position, out obuSize);
                    if (bytesRead == 0 || position + bytesRead + obuSize > rtpPayload.Length)
                    {
                        break;
                    }
                    position += bytesRead;
                }
                else
                {
                    // Last element - size is remainder of payload
                    obuSize = rtpPayload.Length - position;
                }

                if (obuSize <= 0 || position + obuSize > rtpPayload.Length)
                {
                    break;
                }

                byte[] obuData = new byte[obuSize];
                Buffer.BlockCopy(rtpPayload, position, obuData, 0, (int)obuSize);
                position += (int)obuSize;

                // Handle fragmentation
                bool isFirstElement = (elementIndex == 0);
                bool isLastElement = (wField == 0 && position >= rtpPayload.Length) || (wField > 0 && elementIndex == wField - 1);

                if (isFirstElement && zBit)
                {
                    // This is a continuation of a previous fragment
                    fragmentBuffer.Write(obuData, 0, obuData.Length);

                    if (!yBit || !isLastElement)
                    {
                        // Fragment complete
                        byte[] completeObu = fragmentBuffer.ToArray();
                        fragmentBuffer.SetLength(0);
                        fragmentInProgress = false;
                        obuList.Add(completeObu);
                    }
                }
                else if (isLastElement && yBit)
                {
                    // This OBU continues in the next packet
                    fragmentBuffer.SetLength(0);
                    fragmentBuffer.Write(obuData, 0, obuData.Length);
                    fragmentInProgress = true;
                }
                else
                {
                    // Complete OBU
                    if (fragmentInProgress && isFirstElement)
                    {
                        fragmentBuffer.Write(obuData, 0, obuData.Length);
                        byte[] completeObu = fragmentBuffer.ToArray();
                        fragmentBuffer.SetLength(0);
                        fragmentInProgress = false;
                        obuList.Add(completeObu);
                    }
                    else
                    {
                        obuList.Add(obuData);
                    }
                }

                elementIndex++;

                // If wField > 0 and we've processed all elements, stop
                if (wField > 0 && elementIndex >= wField)
                {
                    break;
                }
            }

            return obuList;
        }

        /// <summary>
        /// Creates an OBU with size field set in the header.
        /// </summary>
        private byte[] CreateObuWithSizeField(byte[] obu)
        {
            if (obu == null || obu.Length == 0)
            {
                return obu;
            }

            // Check if OBU already has size field set
            bool hasSize = (obu[0] & 0x02) != 0;
            if (hasSize)
            {
                return obu;
            }

            // Determine header size
            bool hasExtension = (obu[0] & 0x04) != 0;
            int headerSize = hasExtension ? 2 : 1;
            int payloadSize = obu.Length - headerSize;

            // Create new OBU with size field
            byte[] sizeField = AV1Packetiser.EncodeLeb128(payloadSize);
            byte[] result = new byte[headerSize + sizeField.Length + payloadSize];

            // Copy header with has_size_field bit set
            result[0] = (byte)(obu[0] | 0x02);
            if (hasExtension)
            {
                result[1] = obu[1];
            }

            // Copy size field
            Buffer.BlockCopy(sizeField, 0, result, headerSize, sizeField.Length);

            // Copy payload
            Buffer.BlockCopy(obu, headerSize, result, headerSize + sizeField.Length, payloadSize);

            return result;
        }

        /// <summary>
        /// Checks if the OBU list contains a key frame indicator (sequence header).
        /// </summary>
        protected bool CheckKeyFrame(List<byte[]> obuList)
        {
            foreach (var obu in obuList)
            {
                if (obu != null && obu.Length > 0)
                {
                    var obuType = AV1Packetiser.GetObuType(obu[0]);
                    if (obuType == AV1Packetiser.ObuType.OBU_SEQUENCE_HEADER)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Resets the depacketiser state.
        /// </summary>
        public void Reset()
        {
            _previousTimestamp = 0;
            _temporaryRtpPayloads.Clear();
            _fragmentBuffer.SetLength(0);
            //_fragmentInProgress = false;
        }
    }
}

