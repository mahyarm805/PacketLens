package com.packetlens.di

import android.content.Context
import com.packetlens.capture.AppResolver
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideAppResolver(@ApplicationContext context: Context): AppResolver {
        return AppResolver(context)
    }
}
