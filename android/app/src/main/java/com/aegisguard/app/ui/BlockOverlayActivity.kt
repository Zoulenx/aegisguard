package com.aegisguard.app.ui

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegisguard.app.security.LockManager

/**
 * Pantalla de intervención tranquila al bloquear contenido explícito o disparadores.
 * Sin botones de pago, sin monedas y sin atajos para saltar el bloqueo.
 */
class BlockOverlayActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val reason = intent.getStringExtra(EXTRA_REASON) ?: "Contenido explícito bloqueado"
        val sourceApp = intent.getStringExtra(EXTRA_SOURCE_APP) ?: "Aplicación"
        val lockManager = LockManager.getInstance(this)

        setContent {
            BlockOverlayScreen(
                sourceApp = sourceApp,
                reason = reason,
                onActivatePanic = {
                    lockManager.activatePanicMode(60)
                    goToHomeScreen()
                },
                onGoHome = { goToHomeScreen() }
            )
        }
    }

    private fun goToHomeScreen() {
        val home = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(home)
        finish()
    }

    companion object {
        const val EXTRA_REASON = "extra_reason"
        const val EXTRA_SOURCE_APP = "extra_source_app"
    }
}

@Composable
private fun BlockOverlayScreen(
    sourceApp: String,
    reason: String,
    onActivatePanic: () -> Unit,
    onGoHome: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0B1120))
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = Color(0xFF111827)),
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "AegisGuard",
                    color = Color(0xFF38BDF8),
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Contenido Bloqueado",
                    color = Color.White,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.ExtraBold,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Respira profundo 10 segundos. Este bloqueo protege el compromiso que elegiste. No existen monedas ni atajos para desactivarlo.",
                    color = Color(0xFF9CA3AF),
                    fontSize = 14.sp,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(16.dp))
                Surface(
                    color = Color(0xFF0F172A),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text("Origen: $sourceApp", color = Color(0xFF9CA3AF), fontSize = 12.sp)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(reason, color = Color(0xFFFCA5A5), fontSize = 13.sp, fontWeight = FontWeight.Medium)
                    }
                }
                Spacer(modifier = Modifier.height(20.dp))
                Button(
                    onClick = onActivatePanic,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Activar Botón de Pánico (Bloquear redes 60 min)")
                }
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedButton(
                    onClick = onGoHome,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Salir a la pantalla principal", color = Color.White)
                }
            }
        }
    }
}
