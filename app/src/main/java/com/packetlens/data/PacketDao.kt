package com.packetlens.data

import androidx.room.*
import com.packetlens.data.entity.CapturedPacketEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface PacketDao {
    @Query("SELECT * FROM captured_packets ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentPackets(limit: Int = 500): Flow<List<CapturedPacketEntity>>

    @Query("SELECT * FROM captured_packets WHERE id = :id")
    suspend fun getPacketById(id: Long): CapturedPacketEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPacket(packet: CapturedPacketEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPackets(packets: List<CapturedPacketEntity>)

    @Query("DELETE FROM captured_packets")
    suspend fun deleteAll()

    @Query("SELECT COUNT(*) FROM captured_packets")
    suspend fun getCount(): Int

    @Query("SELECT * FROM captured_packets WHERE protocol = :protocol ORDER BY timestamp DESC LIMIT :limit")
    fun getPacketsByProtocol(protocol: String, limit: Int = 500): Flow<List<CapturedPacketEntity>>

    @Query("SELECT * FROM captured_packets WHERE httpHost LIKE '%' || :query || '%' OR dnsQuery LIKE '%' || :query || '%' ORDER BY timestamp DESC LIMIT :limit")
    fun searchPackets(query: String, limit: Int = 500): Flow<List<CapturedPacketEntity>>
}
