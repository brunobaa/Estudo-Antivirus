# Aula 1: Assinaturas por hash

## 1. A ideia em uma frase

> Se eu já vi esse arquivo exato antes e ele era malware, ele continua sendo malware.

O antivírus não guarda cópias dos vírus. Ele guarda só a **impressão digital** (o hash) de cada um.

## 2. O que é um hash

Uma função hash pega uma entrada de **qualquer tamanho** e devolve um resumo de **tamanho fixo**:

```
  "ola mundo"            ┌──────────┐
  (9 bytes)        ────► │          │ ───► 2220622b...6d0b879f  (64 chars)
                         │ SHA-256  │
  windows.iso            │          │
  (5.000.000.000 bytes)─►│          │ ───► (outros 64 chars)
                         └──────────┘
```

### As 4 propriedades que importam para o antivírus

| Propriedade | Significado | Consequência |
|---|---|---|
| Determinística | mesmo arquivo → sempre o mesmo hash | dá para comparar com uma lista |
| Tamanho fixo | 1 KB ou 5 GB → 64 caracteres | a base de assinaturas fica pequena |
| Efeito avalanche | mudou 1 bit → muda ~metade do hash | não existe hash "parecido" |
| Resistente a colisão | impossível achar 2 arquivos com o mesmo hash | não acusa um arquivo inocente por azar |

### Efeito avalanche, visto de perto

```
  "ola mundo"  ──► 2220622b 62ffa648 847c91cd 587a2276 ...
  "ola mundO"  ──► 4225adbb 900f08b1 e31ab23a 660e26fe ...
                   ▲▲▲▲▲▲▲▲ ▲▲▲▲▲▲▲▲ ▲▲▲▲▲▲▲▲ ▲▲▲▲▲▲▲▲
                   tudo diferente, por causa de UMA letra
```

O teste `test_efeito_avalanche` em `tests/test_hash.py` prova isso de verdade.

## 3. MD5, SHA-1 e SHA-256

```
  MD5     ████████████████████████████████                                  32 chars (128 bits)  ❌ quebrado
  SHA-1   ████████████████████████████████████████                          40 chars (160 bits)  ❌ quebrado
  SHA-256 ████████████████████████████████████████████████████████████████  64 chars (256 bits)  ✅ seguro
```

"Quebrado" quer dizer que alguém conseguiu fabricar **colisões**: dois arquivos
diferentes com o mesmo hash. Em 2012, o malware **Flame** usou uma colisão de MD5
para falsificar um certificado da Microsoft e se passar por uma atualização do Windows.

Mesmo assim, muitas bases antigas ainda publicam MD5. Por isso o nosso motor
descobre o algoritmo **pelo tamanho** do hash (32, 40 ou 64) e aceita os três.

## 4. Como o nosso motor funciona

```
                    superav/assinaturas/*.txt
                   ┌──────────────────────────────────┐
  inicialização    │ 275a021b...  EICAR-Test-File     │
  (uma vez só) ──► │ abb4e44c...  Teste.SuperAV.Falso │ ──► dict na memória
                   └──────────────────────────────────┘     {hash: nome}
                                                                 │
  ───────────────────────────────────────────────────────────────┼──────
                                                                 │
  para cada         ┌────────────────────┐                       ▼
  arquivo:  ──────► │ arquivo.hash()     │ ──► abb4e44c... ──► está no dict?
                    │ lê em blocos de 1MB│                    ┌────┴────┐
                    └────────────────────┘                   SIM       NÃO
                                                              ▼         ▼
                                                     🚨 não passou   ✅ passou
                                                  Teste.SuperAV.Falso
```

### Por que um `dict` e não uma lista?

```
  lista: [h1, h2, h3, ... h1.000.000]     dict / set: {h1, h2, ... h1.000.000}
          ▲   ▲   ▲            ▲                          │
          compara um por um    │                          └─► vai direto na "gaveta" certa
          até 1.000.000 comparações                          ~1 comparação
          O(n)                                               O(1)
```

O ClamAV tem milhões de assinaturas. Com uma lista, cada arquivo levaria
segundos; com uma tabela hash, leva microssegundos.

### Por que ler em blocos?

```
  arquivo de 4 GB
  ┌──────┬──────┬──────┬─────┬──────┐
  │ 1 MB │ 1 MB │ 1 MB │ ... │ 1 MB │
  └──┬───┴──┬───┴──┬───┴─────┴──┬───┘
     └──────┴──────┴─── update() ┘──► SHA-256 vai sendo atualizado aos poucos
                                      memória usada: só 1 MB
```

O `hashlib` permite ir alimentando o hash com `update()`, então nunca precisamos
carregar o arquivo inteiro na memória.

## 5. O EICAR e o "falso vírus"

O **EICAR** é um arquivo de teste padronizado pela indústria: é texto puro e
inofensivo, mas **todo antivírus do mundo** tem a assinatura dele. Ele já está na
nossa base.

Se você criar um EICAR no seu PC (o texto está em https://www.eicar.org), o
**Windows Defender provavelmente vai apagá-lo antes** do nosso antivírus ver.
Isso é a mesma lição na prática: o Defender também tem esse hash na base dele.

Por isso criamos o nosso próprio `amostras/teste/falso-virus.txt`, um texto
comum cujo hash colocamos na base como `Teste.SuperAV.FalsoVirus`. O Defender não
conhece esse hash, mas o nosso antivírus conhece.

### Detalhe importante: o `.gitattributes`

O Git no Windows costuma trocar quebras de linha (`\n` ↔ `\r\n`). Isso muda os bytes
do arquivo, e mudar bytes muda o hash. O arquivo `.gitattributes` marca a pasta
`amostras/` como binária para o Git nunca mexer nela.

## 6. A grande fraqueza

```
  vírus original ──► hash A ──► está na base ──► 🚨 pego
       │
       │  o autor adiciona 1 byte qualquer no final
       ▼
  vírus "novo"   ──► hash B ──► não está na base ──► ✅ passou  😱
```

Isso se chama **polimorfismo**: malwares modernos mudam a si mesmos a cada
infecção justamente para gerar hashes novos. O teste `test_um_byte_a_mais_escapa`
mostra isso acontecendo no nosso motor.

| Hash é bom para | Hash é ruim para |
|---|---|
| Malware conhecido e idêntico | Variantes e malware novo |
| Velocidade (microssegundos) | Qualquer arquivo modificado |
| Quase zero falso positivo | Malware polimórfico |

É por isso que o roteiro continua: magic bytes, entropia, YARA e fuzzy hashing
existem para tapar esse buraco.

## 7. Mão na massa

```powershell
.venv\Scripts\Activate.ps1

# ver os 3 hashes de um arquivo
python -m superav hash amostras\limpos\ola.txt

# escanear só com o motor de hash
python -m superav escanear amostras --motores hash

# "ensinar" o antivírus a reconhecer um arquivo seu
python -m superav adicionar-assinatura amostras\limpos\notas.csv --nome Teste.Minha.Ameaca
python -m superav escanear amostras --motores hash
```

O último comando grava em `superav/assinaturas/minhas.txt`. Apague esse arquivo
depois do exercício para o `notas.csv` voltar a ser "limpo".

## 8. Exercícios

1. Rode `python -m superav hash` no `falso-virus.txt`. Copie o arquivo, abra a cópia,
   adicione um espaço no final e rode o `hash` de novo. O que aconteceu com o scan?
2. Compare `Get-FileHash amostras\limpos\ola.txt` (PowerShell) com o nosso comando
   `hash`. Os valores batem? Por quê?
3. Com 64 caracteres hexadecimais, quantos hashes SHA-256 diferentes existem?
   (Dica: cada caractere hex tem 16 possibilidades.) Por que isso torna colisões
   acidentais praticamente impossíveis?
4. Desafio: o site MalwareBazaar publica listas de hashes de malware recentes.
   Como você faria para importar uma lista dessas para a pasta `assinaturas/`?

**Próxima aula → Aula 2: Tipo real do arquivo (magic bytes).**
