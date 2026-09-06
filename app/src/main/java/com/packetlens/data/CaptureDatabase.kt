package com.packetlens.data

import androidx.room.Database
import androidx.room.RoomDatabase
import com.packetlens.data.entity.CapturedPacketEntity

@Database(
    entities = [CapturedPacketEntity::class],
    version = 1,
    exportSchema = false
)
abstract class CaptureDatabase : RoomDatabase() {
    abstract fun packetDao(): PacketDao
}
