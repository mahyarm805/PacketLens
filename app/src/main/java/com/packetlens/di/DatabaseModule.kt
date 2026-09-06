package com.packetlens.di

import android.content.Context
import androidx.room.Room
import com.packetlens.data.CaptureDatabase
import com.packetlens.data.PacketDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): CaptureDatabase {
        return Room.databaseBuilder(
            context,
            CaptureDatabase::class.java,
            "packetlens.db"
        )
            .fallbackToDestructiveMigration()
            .build()
    }

    @Provides
    @Singleton
    fun providePacketDao(database: CaptureDatabase): PacketDao {
        return database.packetDao()
    }
}
