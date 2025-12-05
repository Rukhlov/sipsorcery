//-----------------------------------------------------------------------------
// Filename: AV1Packetiser.cs
//
// Description: The AV1Packetiser class provides methods to packetize AV1 Open Bitstream Units (OBUs)
// for transmission over RTP (Real-time Transport Protocol). It includes functionalities to parse
// AV1 OBUs from a bitstream, construct RTP aggregation headers, and handle fragmentation of large OBUs.
// The class supports single OBU packets, aggregation packets, as well as fragmentation.
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

namespace SIPSorcery.net.RTP.Packetisation
{
    /// <summary>
    /// Provides methods to packetize AV1 Open Bitstream Units (OBUs) for RTP transmission.
    /// </summary>
    /// <remarks>
    /// AV1 RTP Aggregation Header Structure:
    /// 
    ///  0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+
    /// |Z|Y| W |N|-|-|-|
    /// +-+-+-+-+-+-+-+-+
    /// 
    /// Z: MUST be set to 1 if the first OBU element is an OBU fragment that is a continuation
    ///    of an OBU fragment from the previous packet, and MUST be set to 0 otherwise.
    /// Y: MUST be set to 1 if the last OBU element is an OBU fragment that will continue in
    ///    the next packet, and MUST be set to 0 otherwise.
    /// W: Two bit field that describes the number of OBU elements in the packet. This field MUST
    ///    be set equal to 0 or equal to the number of OBU elements contained in the packet.
    ///    If set to 0, each OBU element MUST be preceded by a length field.
    ///    If not set to 0, the last OBU element MUST NOT be preceded by a length field.
    /// N: MUST be set to 1 if the packet is the first packet of a coded video sequence, 0 otherwise.
    /// 
    /// OBU Header Structure:
    /// 
    /// +-+-+-+-+-+-+-+-+
    /// |0|type |X|S|0|
    /// +-+-+-+-+-+-+-+-+
    /// 
    /// type: OBU type (4 bits)
    /// X: extension flag (1 bit)
    /// S: has_size_field flag (1 bit)
    /// </remarks>
    public class AV1Packetiser
    {
        /// <summary>
        /// Size of the AV1 RTP aggregation header in bytes.
        /// </summary>
        public const int AV1_RTP_HEADER_LENGTH = 1;

        /// <summary>
        /// OBU types as defined in the AV1 specification.
        /// </summary>
        public enum ObuType
        {
            OBU_SEQUENCE_HEADER = 1,
            OBU_TEMPORAL_DELIMITER = 2,
            OBU_FRAME_HEADER = 3,
            OBU_TILE_GROUP = 4,
            OBU_METADATA = 5,
            OBU_FRAME = 6,
            OBU_REDUNDANT_FRAME_HEADER = 7,
            OBU_TILE_LIST = 8,
            OBU_PADDING = 15
        }

        /// <summary>
        /// Represents an AV1 OBU element ready for RTP transmission.
        /// </summary>
        public struct AV1Obu
        {
            /// <summary>
            /// The OBU data bytes.
            /// </summary>
            public byte[] OBU { get; }

            /// <summary>
            /// Indicates if this is the last OBU in the frame.
            /// </summary>
            public bool IsLast { get; }

            /// <summary>
            /// The OBU type.
            /// </summary>
            public ObuType Type { get; }

            public AV1Obu(byte[] obu, bool isLast, ObuType type)
            {
                OBU = obu;
                IsLast = isLast;
                Type = type;
            }
        }

        /// <summary>
        /// Parses OBUs from an AV1 bitstream (low overhead bitstream format).
        /// </summary>
        /// <param name="bitstream">The AV1 bitstream containing OBUs.</param>
        /// <returns>An enumerable of parsed OBUs.</returns>
        public static IEnumerable<AV1Obu> ParseObus(byte[] bitstream)
        {
            if (bitstream == null || bitstream.Length == 0)
            {
                yield break;
            }

            int position = 0;

            while (position < bitstream.Length)
            {
                if (position >= bitstream.Length)
                {
                    break;
                }

                // Parse OBU header (1 byte minimum)
                byte obuHeader = bitstream[position];

                // forbidden_bit (1) | obu_type (4) | obu_extension_flag (1) | obu_has_size_field (1) | reserved (1)
                bool forbiddenBit = (obuHeader & 0x80) != 0;
                if (forbiddenBit)
                {
                    // Invalid OBU, forbidden bit must be 0
                    break;
                }

                ObuType obuType = (ObuType)((obuHeader >> 3) & 0x0F);
                bool hasExtension = (obuHeader & 0x04) != 0;
                bool hasSizeField = (obuHeader & 0x02) != 0;

                int headerSize = 1;
                position++;

                // Parse extension header if present
                if (hasExtension)
                {
                    if (position >= bitstream.Length)
                    {
                        break;
                    }
                    headerSize++;
                    position++;
                }

                // Parse size field if present (leb128 encoded)
                long obuSize;
                if (hasSizeField)
                {
                    int sizeFieldBytes = ReadLeb128(bitstream, position, out obuSize);
                    if (sizeFieldBytes == 0)
                    {
                        break;
                    }
                    position += sizeFieldBytes;
                }
                else
                {
                    // If no size field, the OBU continues to the end of the bitstream
                    obuSize = bitstream.Length - position;
                }

                if (position + obuSize > bitstream.Length)
                {
                    break;
                }

                // Extract the complete OBU (header + payload)
                int totalObuSize = headerSize + (hasSizeField ? GetLeb128Size(obuSize) : 0) + (int)obuSize;
                int obuStartPosition = position - headerSize - (hasSizeField ? GetLeb128Size(obuSize) : 0);

                // For RTP, we strip the size field from the OBU
                byte[] obuData = CreateObuWithoutSizeField(bitstream, obuStartPosition, headerSize, hasExtension, obuSize);

                position += (int)obuSize;

                bool isLast = position >= bitstream.Length;

                // Skip temporal delimiter OBUs as they should not be transmitted in RTP
                if (obuType != ObuType.OBU_TEMPORAL_DELIMITER)
                {
                    yield return new AV1Obu(obuData, isLast, obuType);
                }
            }
        }

        /// <summary>
        /// Creates the AV1 RTP aggregation header.
        /// </summary>
        /// <param name="startsWithFragment">True if the packet starts with an OBU fragment continuation (Z bit).</param>
        /// <param name="endsWithFragment">True if the packet ends with an OBU fragment that continues (Y bit).</param>
        /// <param name="obuCount">Number of OBU elements in the packet (0-3, used for W field).</param>
        /// <param name="isNewCodedVideoSequence">True if this is the first packet of a coded video sequence (N bit).</param>
        /// <returns>The aggregation header byte.</returns>
        /// <remarks>
        ///  0 1 2 3 4 5 6 7
        /// +-+-+-+-+-+-+-+-+
        /// |Z|Y| W |N|-|-|-|
        /// +-+-+-+-+-+-+-+-+
        /// </remarks>
        public static byte CreateAggregationHeader(bool startsWithFragment, bool endsWithFragment, int obuCount, bool isNewCodedVideoSequence)
        {
            byte header = 0;

            if (startsWithFragment)
            {
                header |= 0x80; // Z bit
            }

            if (endsWithFragment)
            {
                header |= 0x40; // Y bit
            }

            // W field (2 bits): number of OBU elements, 0 means use length fields for all
            int w = Math.Min(obuCount, 3);
            header |= (byte)((w & 0x03) << 4);

            if (isNewCodedVideoSequence)
            {
                header |= 0x08; // N bit
            }

            return header;
        }

        /// <summary>
        /// Packetizes a list of OBUs into RTP payloads with proper fragmentation.
        /// </summary>
        /// <param name="obus">The OBUs to packetize.</param>
        /// <param name="maxPayloadSize">Maximum RTP payload size.</param>
        /// <param name="isNewCodedVideoSequence">True if this is a new coded video sequence.</param>
        /// <returns>List of RTP payloads.</returns>
        public static IEnumerable<byte[]> Packetize(IEnumerable<AV1Obu> obus, int maxPayloadSize, bool isNewCodedVideoSequence)
        {
            var obuList = new List<AV1Obu>(obus);
            if (obuList.Count == 0)
            {
                yield break;
            }

            bool isFirstPacket = true;
            int obuIndex = 0;

            while (obuIndex < obuList.Count)
            {
                var currentObu = obuList[obuIndex];
                byte[] obuData = currentObu.OBU;

                // Check if OBU fits in a single packet (with aggregation header and size field)
                int sizeFieldLength = GetLeb128Size(obuData.Length);
                int requiredSize = AV1_RTP_HEADER_LENGTH + sizeFieldLength + obuData.Length;

                if (requiredSize <= maxPayloadSize)
                {
                    // Try to aggregate multiple OBUs
                    var aggregatedPayload = new List<byte>();
                    var aggregatedObus = new List<byte[]>();
                    int aggregatedCount = 0;
                    bool lastObuIsLast = false;

                    while (obuIndex < obuList.Count && aggregatedCount < 3)
                    {
                        var obu = obuList[obuIndex];
                        int obuSizeField = GetLeb128Size(obu.OBU.Length);
                        int additionalSize = obuSizeField + obu.OBU.Length;

                        // For the last OBU in W>0 mode, we don't need size field
                        if (aggregatedCount > 0)
                        {
                            // Check if adding this OBU would exceed max size
                            // (consider that last OBU won't need size field if we use W field)
                            int testSize = AV1_RTP_HEADER_LENGTH;
                            for (int i = 0; i < aggregatedObus.Count; i++)
                            {
                                testSize += GetLeb128Size(aggregatedObus[i].Length) + aggregatedObus[i].Length;
                            }
                            testSize += obu.OBU.Length; // Last one without size field

                            if (testSize > maxPayloadSize)
                            {
                                break;
                            }
                        }
                        else
                        {
                            // First OBU - check with its size field
                            if (AV1_RTP_HEADER_LENGTH + obu.OBU.Length > maxPayloadSize)
                            {
                                break;
                            }
                        }

                        aggregatedObus.Add(obu.OBU);
                        aggregatedCount++;
                        lastObuIsLast = obu.IsLast;
                        obuIndex++;
                    }

                    if (aggregatedCount > 0)
                    {
                        // Create aggregation header
                        bool isNewSeq = isFirstPacket && isNewCodedVideoSequence;
                        byte aggHeader = CreateAggregationHeader(false, false, aggregatedCount, isNewSeq);
                        aggregatedPayload.Add(aggHeader);

                        // Add OBUs with size fields (except last one when W > 0)
                        for (int i = 0; i < aggregatedObus.Count; i++)
                        {
                            bool isLastObuInPacket = (i == aggregatedObus.Count - 1);

                            if (!isLastObuInPacket || aggregatedCount == 0)
                            {
                                // Add size field
                                byte[] sizeBytes = EncodeLeb128(aggregatedObus[i].Length);
                                aggregatedPayload.AddRange(sizeBytes);
                            }

                            aggregatedPayload.AddRange(aggregatedObus[i]);
                        }

                        isFirstPacket = false;
                        yield return aggregatedPayload.ToArray();
                    }
                }
                else
                {
                    // OBU needs fragmentation
                    int offset = 0;
                    bool isFirstFragment = true;

                    while (offset < obuData.Length)
                    {
                        int remainingData = obuData.Length - offset;
                        int fragmentSize = Math.Min(remainingData, maxPayloadSize - AV1_RTP_HEADER_LENGTH);

                        bool isLastFragment = (offset + fragmentSize >= obuData.Length);

                        // Create aggregation header for fragment
                        bool startsWithFragment = !isFirstFragment;
                        bool endsWithFragment = !isLastFragment;
                        bool isNewSeq = isFirstPacket && isNewCodedVideoSequence && isFirstFragment;

                        byte aggHeader = CreateAggregationHeader(startsWithFragment, endsWithFragment, 1, isNewSeq);

                        // Build fragment packet
                        byte[] fragment = new byte[AV1_RTP_HEADER_LENGTH + fragmentSize];
                        fragment[0] = aggHeader;
                        Buffer.BlockCopy(obuData, offset, fragment, AV1_RTP_HEADER_LENGTH, fragmentSize);

                        offset += fragmentSize;
                        isFirstFragment = false;
                        isFirstPacket = false;

                        yield return fragment;
                    }

                    obuIndex++;
                }
            }
        }

        /// <summary>
        /// Creates an OBU without the size field (for RTP transmission).
        /// </summary>
        private static byte[] CreateObuWithoutSizeField(byte[] bitstream, int obuStart, int headerSize, bool hasExtension, long payloadSize)
        {
            // OBU for RTP: header (with size field bit cleared) + extension (if present) + payload
            int newHeaderSize = hasExtension ? 2 : 1;
            byte[] result = new byte[newHeaderSize + payloadSize];

            // Copy header byte and clear the has_size_field bit
            result[0] = (byte)(bitstream[obuStart] & 0xFD); // Clear bit 1 (has_size_field)

            if (hasExtension)
            {
                result[1] = bitstream[obuStart + 1];
            }

            // Calculate payload start position in original bitstream
            int originalHeaderSize = headerSize;
            int sizeFieldSize = GetLeb128Size(payloadSize);
            int payloadStart = obuStart + originalHeaderSize + sizeFieldSize;

            // Copy payload
            Buffer.BlockCopy(bitstream, payloadStart, result, newHeaderSize, (int)payloadSize);

            return result;
        }

        /// <summary>
        /// Reads a leb128 encoded value from the bitstream.
        /// </summary>
        /// <param name="data">Source data.</param>
        /// <param name="offset">Starting offset.</param>
        /// <param name="value">Output value.</param>
        /// <returns>Number of bytes consumed, or 0 if error.</returns>
        public static int ReadLeb128(byte[] data, int offset, out long value)
        {
            value = 0;
            int bytesRead = 0;

            for (int i = 0; i < 8; i++) // leb128 max 8 bytes for 56-bit value
            {
                if (offset + i >= data.Length)
                {
                    return 0;
                }

                byte b = data[offset + i];
                value |= (long)(b & 0x7F) << (i * 7);
                bytesRead++;

                if ((b & 0x80) == 0)
                {
                    break;
                }
            }

            return bytesRead;
        }

        /// <summary>
        /// Encodes a value as leb128.
        /// </summary>
        /// <param name="value">Value to encode.</param>
        /// <returns>Encoded bytes.</returns>
        public static byte[] EncodeLeb128(long value)
        {
            var bytes = new List<byte>();

            do
            {
                byte b = (byte)(value & 0x7F);
                value >>= 7;

                if (value != 0)
                {
                    b |= 0x80;
                }

                bytes.Add(b);
            }
            while (value != 0);

            return bytes.ToArray();
        }

        /// <summary>
        /// Gets the size of a leb128 encoded value.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns>Number of bytes needed to encode the value.</returns>
        public static int GetLeb128Size(long value)
        {
            int size = 0;

            do
            {
                size++;
                value >>= 7;
            }
            while (value != 0);

            return size;
        }

        /// <summary>
        /// Gets the OBU type from an OBU header byte.
        /// </summary>
        /// <param name="headerByte">The first byte of the OBU.</param>
        /// <returns>The OBU type.</returns>
        public static ObuType GetObuType(byte headerByte)
        {
            return (ObuType)((headerByte >> 3) & 0x0F);
        }

        /// <summary>
        /// Checks if an OBU is a key frame indicator (sequence header).
        /// </summary>
        /// <param name="obu">The OBU to check.</param>
        /// <returns>True if this OBU indicates a key frame.</returns>
        public static bool IsKeyFrameObu(AV1Obu obu)
        {
            return obu.Type == ObuType.OBU_SEQUENCE_HEADER;
        }
    }
}

