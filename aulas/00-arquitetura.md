# Aula 0: Como um antivírus é organizado

## 1. Um antivírus não é um detector, são vários

Nenhuma técnica sozinha pega tudo. Cada uma enxerga um "lado" da ameaça:

```
                         ┌─────────────────┐
                         │   arquivo.exe   │
                         └────────┬────────┘
       ┌──────────────┬───────────┼────────────┬───────────────┐
       ▼              ▼           ▼            ▼               ▼
  ┌─────────┐   ┌──────────┐ ┌──────────┐ ┌──────────┐   ┌───────────┐
  │  Hash   │   │   Tipo   │ │ Entropia │ │   YARA   │...│ Reputação │
  │"já vi   │   │"é o que  │ │"parece   │ │"tem um   │   │"o mundo   │
  │ ele?"   │   │ diz ser?"│ │ cifrado?"│ │ padrão?" │   │ conhece?" │
  └────┬────┘   └────┬─────┘ └────┬─────┘ └────┬─────┘   └─────┬─────┘
       ▼             ▼            ▼            ▼               ▼
   ✅ passou    🚨 não passou  🟡 suspeito  ✅ passou       ✅ passou
       └─────────────┴────────────┼────────────┴───────────────┘
                                  ▼
                   ┌───────────────────────────────┐
                   │ Veredito final = o PIOR deles │
                   │         🚨 MALICIOSO          │
                   └───────────────────────────────┘
```

Os antivírus comerciais (Defender, Kaspersky, ClamAV) funcionam assim: vários
**motores** (*engines*) independentes, e um núcleo que junta as respostas.

## 2. A ideia central: um contrato

Para o núcleo conseguir conversar com motores que ainda nem existem, todos
precisam falar a mesma língua. Esse acordo é o **contrato** (em `core/motor.py`):

```
        ENTRADA                   MOTOR                    SAÍDA
  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
  │ Arquivo          │     │ analisar(arquivo)│     │ Resultado        │
  │  .caminho        │ ──► │                  │ ──► │  .veredito       │
  │  .tamanho        │     │  (cada um decide │     │  .detalhe        │
  │  .dados (bytes)  │     │   do seu jeito)  │     │                  │
  └──────────────────┘     └──────────────────┘     └──────────────────┘
```

O núcleo **não sabe** como o motor de hash ou o de YARA decidem; só sabe que
recebem um `Arquivo` e devolvem um `Resultado`. Em programação isso se chama
**polimorfismo**, e é feito com uma classe abstrata (`Motor`, com `ABC`).

## 3. Os vereditos e a gravidade

```
  gravidade:   0          1        2          3            4
            PENDENTE ── ERRO ── LIMPO ── SUSPEITO ── MALICIOSO
               ⏳         ❌       ✅         🟡           🚨
                                   └──── max() escolhe o pior ────►
```

Como o `Veredito` é um `IntEnum`, cada veredito é também um número, e o veredito
final é só `max(...)`. Um único motor dizendo "malicioso" basta para condenar
o arquivo, porque no mundo da segurança é melhor desconfiar a mais do que a menos.

- **PENDENTE**: o motor ainda não foi construído (esqueleto com `pronto = False`).
- **ERRO**: o motor quebrou. Fica abaixo de LIMPO porque um bug não diz
  nada sobre o arquivo.

## 4. Plugins: motores que se registram sozinhos

```
  superav/motores/                        core/registro.py
  ┌──────────────┐  @registrar            ┌──────────────────────┐
  │ hash.py      │ ─────────────────────► │ lista de chamada:    │
  │ tipo.py      │ ─────────────────────► │  [Hash, Tipo,        │
  │ entropia.py  │ ─────────────────────► │   Entropia, ...]     │
  │ (novo).py    │ ─────────────────────► │                      │
  └──────────────┘                        └──────────┬───────────┘
       ▲                                             │ carregar_motores()
       │ motores/__init__.py importa                 ▼
       │ TODOS os .py da pasta                ┌──────────────┐
       └───────────────────────────────────── │   scanner    │
                                              └──────────────┘
```

Adicionar um motor = **criar um arquivo** em `motores/`. Não é preciso editar o
scanner, o relatório nem a CLI. É o princípio **aberto/fechado**: o programa
está aberto para extensão e fechado para modificação.

## 5. Robustez: um motor quebrado não derruba os outros

```
  arquivo ──► Hash ──────► ✅
          ──► YARA ──💥──► try/except ──► ❌ erro (registrado)
          ──► Entropia ──► 🟡            ▲
                                         └── o scan continua normalmente
```

Antivírus analisam arquivos estranhos de propósito, e às vezes o arquivo é feito
justamente para travar o analisador. Por isso cada motor roda dentro de um
`try/except`.

## 6. Desempenho: ler o arquivo uma vez só

Se cada um dos 8 motores lesse o arquivo do disco, seriam 8 leituras. A classe
`Arquivo` lê na primeira vez que alguém pede `.dados` e guarda o conteúdo para
os outros (*lazy loading* + *cache*).

## 7. Mão na massa

```powershell
.venv\Scripts\Activate.ps1
python -m superav motores
python -m superav escanear amostras
python -m unittest discover tests -v
```

Hoje todo motor responde ⏳ pendente. Na próxima aula o primeiro vira ✅ de verdade.

## 8. Exercícios

1. Abra `tests/test_nucleo.py` e leia o motor `AchaPalavraVirus`. Ele é um antivírus
   de verdade, só que bem burro. Por que um antivírus que procura palavras é ruim?
2. Por que `ERRO` tem gravidade **menor** que `LIMPO`? O que aconteceria se fosse maior?
3. Crie `motores/vazio.py` com um motor que marque arquivos de 0 bytes como
   `suspeito`. Rode o scan e veja ele aparecer sem mexer em mais nada.
   (Depois apague: é só um exercício.)

**Próxima aula → Aula 1: Assinaturas por hash.**
