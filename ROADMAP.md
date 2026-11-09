# 🗺️ Roteiro do Super Antivírus

Uma aula por dia. Cada aula ensina um conceito e adiciona uma peça nova ao programa.

```
 Módulo 1: Detecção em arquivos       Módulo 2: Proteção ativa        Módulo 3: Entendendo ameaças
 ┌──────────────────────────────┐     ┌──────────────────────────┐    ┌───────────────────────────┐
 │ 0 Arquitetura (base)    ✅   │     │  8 Quarentena            │    │ 13 Laboratório isolado (VM)│
 │ 1 Hash                  ✅   │     │  9 Tempo real            │    │ 14 Anatomia de um malware  │
 │ 2 Tipo real (magic)     ✅   │ ──► │ 10 Conexões de rede      │ ─► │ 15 Persistência e defesa   │
 │ 3 Entropia              ✅   │     │ 11 Reputação online      │    │ 16 Análise de amostra real │
 │ 4 Estrutura PE (.exe)   ✅   │     │ 12 Painel web            │    └───────────────────────────┘
 │ 5 Regras YARA                │     └──────────────────────────┘
 │ 6 Hash por semelhança        │
 │ 7 Scripts e macros           │
 └──────────────────────────────┘
```

## Módulo 1: Detecção em arquivos (motores)

| Aula | Tema | O que entra no programa | Status |
|---:|---|---|:---:|
| 0 | Arquitetura de um antivírus | Núcleo, motores plugáveis, relatório, CLI, testes | ✅ |
| 1 | Assinaturas por hash | Motor `hash`: SHA-256 + base de assinaturas + EICAR | ✅ |
| 2 | Tipo real do arquivo | Motor `tipo`: magic bytes, extensão falsa/dupla, RLO | ✅ |
| 3 | Entropia | Motor `entropia`: detectar arquivo compactado/criptografado | ✅ |
| 4 | Executáveis do Windows (PE) | Motor `pe`: seções e imports suspeitos (`pefile`) | ✅ |
| 5 | Regras YARA | Motor `yara`: escrever e rodar regras próprias | ⏳ |
| 6 | Fuzzy hashing | Motor `fuzzy`: pegar variantes "parecidas" | ⏳ |
| 7 | Scripts e macros | Motor `scripts`: PowerShell/JS ofuscado, macros | ⏳ |

## Módulo 2: Proteção ativa

| Aula | Tema | O que entra no programa | Status |
|---:|---|---|:---:|
| 8 | Quarentena | Isolar, cifrar e restaurar arquivos | ⏳ |
| 9 | Proteção em tempo real | Vigiar pastas (`watchdog`) | ⏳ |
| 10 | Conexões de rede suspeitas | Processos falando com IPs ruins (`psutil`) | ⏳ |
| 11 | Reputação online | Motor `reputacao`: consulta de hash no VirusTotal | ⏳ |
| 12 | Painel web | Interface com histórico e gráficos (`flask`) | ⏳ |

## Módulo 3: Entendendo as ameaças (do lado do defensor)

| Aula | Tema |
|---:|---|
| 13 | Montando um laboratório isolado (máquina virtual, rede isolada, snapshots) |
| 14 | Anatomia de um malware: tipos (vírus, worm, trojan, ransomware) e como agem |
| 15 | Técnicas de persistência e evasão, e como o nosso antivírus as detecta |
| 16 | Análise estática de uma amostra real dentro do laboratório |

> No Módulo 3 a gente estuda como os malwares funcionam para saber detectá-los,
> usando amostras inofensivas (EICAR, simuladores) e análise dentro da VM.
> Não vamos escrever malware funcional.
