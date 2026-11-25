---
adr: "0021"
titulo: Donaciones en Bitcoin sin custodia
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-002, CMP-006, CMP-008, CMP-017]
sustituye: null
---

## Contexto

El modelo de sostenibilidad es de **donaciones, no de venta**. El feed es siempre gratis e igual
para todos; quien dona recibe reconocimiento, nunca datos antes ni mejores. Las donaciones son solo
en Bitcoin, por Lightning y on-chain, y las recibe Juan como persona física. Las obligaciones
fiscales son de Juan y quedan fuera de este repo.

Requisitos duros:
- **Sin custodia.** Las claves privadas nunca están en el servidor, en el repo ni en Azure.
- **Una dirección on-chain nueva por donación.** Una dirección fija expone el saldo y lo vincula al
  proyecto.
- **Lightning** con una Lightning address o un equivalente sin custodia.
- Coste casi nulo: el presupuesto total es de 100 €/mes y la infraestructura ya gasta 70-85 €.
- La pantalla pública de transparencia necesita leer lo recibido sin datos del donante.

**Hallazgo que condiciona el diseño:** todo nodo Lightning que corre en un servidor guarda su
semilla en ese servidor. Pasa con LND, CLN, phoenixd, Alby Hub y los plugins Breez de BTCPay. Es un
monedero caliente. **Lightning no puede vivir en Azure** sin romper el primer requisito.

## Decisión (propuesta)

1. **On-chain: una dirección nueva por donación, servida por la API en modo solo lectura.**
   - Opción preferida: **lista de direcciones pregeneradas offline** en el monedero frío de Juan.
     La lista se guarda en Key Vault como secret, nunca en git. El servidor entrega la siguiente
     dirección sin usar y marca su índice. Si el servidor se compromete, solo se filtran esas
     direcciones, no todo el historial.
   - Opción alternativa: derivar desde una **xpub guardada en Key Vault** (watch-only), respetando
     el gap limit (~20 direcciones sin usar). Su fuga revelaría todas las direcciones pasadas y
     futuras, así que es configuración sensible.
   - Lectura: el job diario consulta los saldos de esas direcciones en una API pública de
     explorador (mempool.space) y guarda solo importe y fecha. Ese proveedor ve las consultas y la
     IP del servidor; se documenta.
2. **Lightning: Phoenix en el móvil de Juan**, con una Lightning address BIP-353 o una oferta
   BOLT12 publicada en DNS (registro gestionado como configuración, no en git). Las claves no tocan
   el servidor. Recibir con liquidez cuesta 0; el primer canal, ~1 % más la comisión de minería.
   Como Phoenix móvil no tiene API, **Juan registra los totales mensuales de Lightning** desde
   Administración (detrás de Access). Cada registro queda en `donation_received` con canal
   `lightning` y una referencia opaca.
3. **Privacidad del donante.**
   - Sin formularios ni cuentas.
   - El endpoint que entrega la dirección no registra IP ni user-agent: se excluye de los logs de
     la API, de App Insights y del log de Cloudflare.
   - La pantalla pública muestra el agregado mensual y la fecha redondeada al día, **nunca el txid**.
   - El reconocimiento es opcional y solo si el donante lo pide.
4. **Privacidad de Juan.** Control de monedas al gastar, para no volver a vincular direcciones. No
   enviar directamente desde esas direcciones a un exchange con KYC si se quiere separar la
   identidad del proyecto.
5. **Interruptor `donations.enabled`** (por defecto `false`). La fase va **después de F4** (F4b) y se
   activa al cerrarla, tras la revisión legal de Juan. Con el interruptor apagado no aparece ningún
   enlace ni dato de donaciones.

## Comparativa (2026-11-25)

| Opción | Custodia y claves | Coste | Mantenimiento | Lectura de cobros | Veredicto |
|---|---|---|---|---|---|
| BTCPay autoalojado | On-chain watch-only (xpub); Lightning con nodo propio (claves en el servidor) o plugin | VPS de 4 GB, nodo pruned de ~80 GB: ≈ 7-10 €/mes | Alto: muchos contenedores y actualizaciones | API Greenfield | Descartado: excesivo para donaciones; Lightning no resuelto ([btcpayserver-docker](https://github.com/btcpayserver/btcpayserver-docker)) |
| BTCPay en un host de terceros | El host ve la xpub; Lightning con el nodo del host (custodia) | Variable | Bajo | API | Descartado: privacidad y Lightning con custodia |
| phoenixd o Alby Hub en Azure | Semilla en la nube | ~0 + canal | Medio | Sí (API o NWC) | **Descartado: rompe el requisito de no custodia en la nube** |
| Alby Hub o phoenixd en un equipo de Juan | Claves en casa | Canal ~1 % + equipo 24/7 | Medio | NWC solo lectura o `limited-access` de phoenixd | Alternativa si se quiere lectura automática de Lightning |
| **On-chain desde Azure (lista pregenerada o xpub en KV) + Phoenix móvil** | Sin claves de gasto en ningún servidor | ≈ 0 € | Bajo | On-chain automática; Lightning manual | **Recomendada** |
| Silent payments (BIP-352) | Dirección estática sin vinculación | 0 | — | El servidor no lee los cobros sin la clave de escaneo | No ahora: poco soporte entre donantes ([estado 2026](https://spark.money/research/bitcoin-silent-payment-adoption-wallet-support-2026)) |
| Wallet of Satoshi | Considerado con custodia | — | — | — | Descartado |

Fuentes:
- Phoenix: [FAQ](https://phoenix.acinq.co/content/faq.md), [API del servidor](https://phoenix.acinq.co/content/server/api.md), [liquidez](https://phoenix.acinq.co/content/server/liquidity.md)
- Zeus: [comisiones del LSP](https://docs.zeusln.app/lsp/fees)
- Alby Hub: [repositorio](https://github.com/getAlby/hub)
- BIP-352: [Bitcoin Optech](https://bitcoinops.org/en/topics/silent-payments/)

La documentación de BTCPay bloqueó la descarga directa; sus datos salen de los README de GitHub y
de resultados de búsqueda que citan la documentación oficial (**SIN VERIFICAR** en la fuente
primaria).

## Consecuencias

- Coste ≈ 0 € y ningún nodo que mantener. Superficie de ataque mínima: en el peor caso se filtra
  información de lectura (la lista de direcciones o la xpub), nunca fondos.
- La cifra de Lightning en la pantalla de transparencia es manual. Se marca como tal.
- Nuevo componente CMP-017 (entrega de direcciones y lectura de cobros, dentro de la API y del job
  diario).
- Secrets nuevos en Key Vault: la lista de direcciones (o la xpub). Requisito de plataforma G-18.

## Evidencia

Informe de investigación del 2026-11-25 con las URL citadas arriba.
