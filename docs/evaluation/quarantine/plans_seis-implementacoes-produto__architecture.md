# Architecture: Seis implementações do produto

## Approach
Cada implementação vira produto fatiando o que já existe, com firmware fina: computação sobre dados públicos (derivação de endereço, formatações, remontagens, retries, countdowns) vai para o bridge Rust no app; o firmware vira info sob chamada (bytes crus + assinatura quando precisa). PIV ganha o núcleo seguro; proximidade liga o BLE; killswitch empacota wipe+transportes+scripts; dongle combina WinUSB + challenge + Ed25519; carteira fia módulo até UI; app acompanha com menus e jornada.

## Components
- piv-seguro: VERIFY/AUTH/PUT/GEN + PIN/PUK NVS + mscp
- proximity-ble: bonding/advertise + agents SO
- killswitch: opcode CDC/HID + gatilhos + scripts erase
- dongle-ed25519: challenge via WinUSB + envelope + verify app
- wallet-produto: ops BLE + NVS + UI + web fetch
- app-screens: menus + controle pós-pareamento + telas Bitcoin + jornada
- thin-firmware: auditoria ficar-vs-mover + bridge + getters mínimos

## Data Flow
App computa/formata → chama device só para segredo/assinatura/RNG/gate → device retorna bytes → app apresenta; transporte → gates → motor → NVS → resposta display-only

## Alternatives Considered
- RSA-3072 no dongle — rejected because usuário escolheu só Ed25519
- Killswitch só físico — rejected because usuário exigiu os dois gatilhos
- Carteira mínima — rejected because usuário exigiu completa
- Tirar assinatura do firmware — rejected because chave privada nunca sai do hardware
