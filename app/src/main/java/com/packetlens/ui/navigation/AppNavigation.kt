package com.packetlens.ui.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.packetlens.ui.screens.ConnectionDetailScreen
import com.packetlens.ui.screens.HomeScreen

@Composable
fun AppNavigation() {
    val navController = rememberNavController()

    NavHost(navController = navController, startDestination = "home") {
        composable("home") {
            HomeScreen(
                onPacketClick = { packetId ->
                    navController.navigate("detail/$packetId")
                }
            )
        }
        composable(
            "detail/{packetId}",
            arguments = listOf(navArgument("packetId") { type = NavType.LongType })
        ) { backStackEntry ->
            val packetId = backStackEntry.arguments?.getLong("packetId") ?: 0L
            ConnectionDetailScreen(
                packetId = packetId,
                onBack = { navController.popBackStack() }
            )
        }
    }
}
