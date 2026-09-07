package com.packetlens.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.packetlens.ui.screens.AppSelectorScreen
import com.packetlens.ui.screens.ConnectionDetailScreen
import com.packetlens.ui.screens.HomeScreen
import com.packetlens.ui.viewmodel.CaptureViewModel
import androidx.hilt.navigation.compose.hiltViewModel

@Composable
fun AppNavigation() {
    val navController = rememberNavController()

    NavHost(navController = navController, startDestination = "home") {
        composable("home") {
            val homeEntry = remember { navController.getBackStackEntry("home") }
            val viewModel: CaptureViewModel = hiltViewModel(homeEntry)
            HomeScreen(
                viewModel = viewModel,
                onPacketClick = { packetId ->
                    navController.navigate("detail/$packetId")
                },
                onAppFilterClick = {
                    navController.navigate("apps")
                }
            )
        }
        composable(
            "detail/{packetId}",
            arguments = listOf(navArgument("packetId") { type = NavType.LongType })
        ) { backStackEntry ->
            val packetId = backStackEntry.arguments?.getLong("packetId") ?: 0L
            val homeEntry = remember(backStackEntry) { navController.getBackStackEntry("home") }
            val viewModel: CaptureViewModel = hiltViewModel(homeEntry)
            ConnectionDetailScreen(
                packetId = packetId,
                onBack = { navController.popBackStack() },
                viewModel = viewModel
            )
        }
        composable("apps") {
            val homeEntry = remember { navController.getBackStackEntry("home") }
            val viewModel: CaptureViewModel = hiltViewModel(homeEntry)
            AppSelectorScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() }
            )
        }
    }
}
