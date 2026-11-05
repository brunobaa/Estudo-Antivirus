# Aula 2: Tipo real do arquivo (magic bytes)

## 1. A ideia em uma frase

> A extensão é o que o arquivo **diz** ser. Os magic bytes são o que ele **é**.

```
                ┌──────────────── nome ────────────────┐ ┌──────── conteúdo ────────┐
  arquivo:       boleto           .pdf                    4D 5A 90 00 41 6D 6F ...
                                   ▲                       ▲
                       qualquer um troca                   o programa que abre o
                       com "Renomear"                      arquivo olha AQUI
```

A extensão é só uma parte do **nome**, e o nome qualquer pessoa troca. Os
primeiros bytes do conteúdo seguem o **formato** do arquivo, e um programa de
verdade **precisa** deles para funcionar.

## 2. O que são magic bytes

Quase todo formato de arquivo começa com uma "assinatura" fixa, escolhida por
quem inventou o formato:

```
  Formato        Primeiros bytes (hex)        Como texto
  ─────────────  ───────────────────────────  ──────────────
  .exe / .dll    4D 5A                        MZ          ◄── iniciais de Mark Zbikowski,
  .png           89 50 4E 47 0D 0A 1A 0A      .PNG....        engenheiro da Microsoft
  .jpg           FF D8 FF                     ...
  .pdf           25 50 44 46 2D               %PDF-
  .zip/.docx     50 4B 03 04                  PK..        ◄── iniciais de Phil Katz,
  .gif           47 49 46 38 39 61            GIF89a          criador do ZIP
  .rar           52 61 72 21 1A 07            Rar!..
  ELF (Linux)    7F 45 4C 46                  .ELF
```

Repare: um `.docx` **é um ZIP**. Abra um Word no 7-Zip e você vai ver um monte de
arquivos XML dentro. Por isso, na nossa tabela, ZIP aceita as extensões `zip docx
xlsx pptx jar apk ...`.

### Nem sempre começa no byte 0

```
  MP4:   00 00 00 20 │ 66 74 79 70 │ 69 73 6F 6D
         └─tamanho──┘ └── "ftyp" ──┘
         posição 0     posição 4  ◄── a assinatura está aqui

  WEBP:  52 49 46 46 │ xx xx xx xx │ 57 45 42 50
         └─ "RIFF" ─┘ └──tamanho──┘ └─ "WEBP" ─┘
         RIFF sozinho não basta: WAV e AVI também começam com RIFF.
         Por isso conferimos uma 2ª parte, na posição 8.
```

## 3. Por que isso engana tanta gente

O Windows vem configurado para **esconder as extensões conhecidas**:

```
  o que existe no disco:        o que o usuário vê no Explorer:
  ┌──────────────────────┐      ┌──────────────────────┐
  │ foto.jpg.exe         │ ───► │ 🖼️ foto.jpg          │  ◄── ".exe" sumiu!
  └──────────────────────┘      └──────────────────────┘
                                  e o ícone pode ser trocado para
                                  parecer uma imagem
```

> 💡 Ligue no seu PC: Explorer → Exibir → Mostrar → **Extensões de nomes de arquivos**.
> É uma das proteções mais simples e mais eficazes que existem.

## 4. Os 4 truques que o motor pega

### Truque 1: executável disfarçado

```
  boleto.pdf ──► cabeçalho: 4D 5A ("MZ") ──► é um .exe!  ──► 🚨 não passou
                                                           "disfarçado de .pdf"
```

Se alguém der dois cliques, o Windows abre pelo tipo da extensão (leitor de
PDF), que dá erro. Mas basta renomear, ou fazer outro programa executá-lo, para
virar um programa. O conteúdo não mente: é um executável.

### Truque 2: extensão dupla

```
  "foto.jpg.exe".split(".")  ──►  ["foto", "jpg", "exe"]
                                           ▲       ▲
                                  isca inocente   o que o Windows realmente usa
```

Uma variação usa espaços para empurrar o `.exe` para fora da tela:
`foto.jpg                                  .exe`. Nosso motor aplica `.strip()`
em cada parte, então o truque não funciona com ele.

### Truque 3: o caractere invisível RLO

O Unicode tem caracteres invisíveis para escrever em árabe e hebraico, idiomas
da direita para a esquerda. O **RLO** (U+202E, *Right-to-Left Override*) faz
tudo que vem depois dele aparecer **invertido**:

```
  bytes reais do nome:   f a t u r a [RLO] f d p . e x e
                                       └──── invertido ────┐
  o que aparece na tela: f a t u r a  e x e . p d f   ◄────┘
                         "faturaexe.pdf"   parece PDF, mas é .exe!
```

Esse truque já foi usado em campanhas reais de malware por e-mail. Um nome com
RLO quase nunca tem motivo legítimo, então o motor marca como malicioso direto.

> 🔍 Curiosidade da aula: escrevendo o motor, a ferramenta de arquivos converteu
> `\u202e` no caractere invisível de verdade, dentro do código-fonte. Ninguém
> veria! Por isso os testes usam `chr(0x202E)` e o código usa só escapes visíveis.
> O GitHub mostra um aviso amarelo quando um arquivo tem esses caracteres,
> justamente por causa de ataques assim (pesquise "Trojan Source").

### Truque 4: compactado disfarçado

```
  documento.pdf ──► cabeçalho: 50 4B 03 04 ("PK") ──► é um ZIP ──► 🟡 suspeito
```

Malwares costumam vir **dentro** de um ZIP para escapar de filtros de e-mail.
Fica como "suspeito" e não "malicioso" porque também acontece por engano.

## 5. A árvore de decisão do motor

```
                          nome tem RLO/LRO?
                         ┌──────┴──────┐
                        SIM           NÃO
                         ▼             ▼
                    🚨 malicioso   conteúdo é executável?
                                 ┌──────┴────────────────┐
                                SIM                     NÃO
                                 ▼                       ▼
                        extensão confere?          extensão dupla?
                      ┌────────┼─────────┐        ┌──────┴──────┐
                     SIM     vazia      NÃO      SIM           NÃO
                      ▼        ▼         ▼        ▼             ▼
                extensão   🟡 sem     🚨 disfar-  🟡 suspeito   extensão confere?
                 dupla?    extensão     çado               ┌──────┴──────┐
                ┌──┴──┐                                   SIM           NÃO
               SIM   NÃO                                   ▼             ▼
                ▼     ▼                                ✅ passou   é ZIP/documento?
         🚨 malicioso ✅ passou                                     ┌─────┴─────┐
                                                                  SIM         NÃO
                                                                   ▼           ▼
                                                             🟡 suspeito   ✅ passou
                                                                          (só informa)
```

## 6. Falsos positivos: a parte difícil

```
  rigoroso demais                              permissivo demais
  ◄──────────────────────────┼──────────────────────────────►
  "foto.jpg que é PNG"       │              "boleto.pdf que é .exe"
  marcado como vírus 😠      │              passou como limpo 😱
  o usuário desinstala       │              o usuário é infectado
  o antivírus                ▼
                       nosso motor fica aqui:
                 executável disfarçado = 🚨
                 ZIP disfarçado        = 🟡
                 imagem trocada        = ✅ (só informa)
```

Um PNG salvo como `.jpg` acontece o tempo todo por engano e não é perigoso.
Escolher **onde** ficar nessa régua é uma das decisões mais importantes de
qualquer antivírus.

## 7. Como o hash e o tipo se completam

```
                         hash                 tipo
  falso-virus.txt   🚨 conhecido         ✅ texto comum
  boleto.pdf        ✅ desconhecido      🚨 .exe disfarçado
  foto.jpg.exe      ✅ desconhecido      🚨 extensão dupla
                    └───────────┬────────────┘
                     cada motor pega o que o outro deixa passar
```

O hash só pega o que **já conhece**. O motor de tipo pega o **truque**,
mesmo num malware que ninguém nunca viu. É a primeira **heurística** do projeto.

## 8. Mão na massa

```powershell
.venv\Scripts\Activate.ps1

# ver os bytes de verdade (como um editor hexadecimal)
python -m superav cabecalho amostras\teste\boleto.pdf
python -m superav cabecalho amostras\teste\imagem.png --bytes 64

# escanear com os dois motores prontos
python -m superav escanear amostras --motores hash,tipo
```

## 9. Exercícios

1. Rode `cabecalho` em arquivos do seu PC: uma foto do celular, um PDF, um `.docx`,
   um programa em `C:\Windows\System32`. Os magic bytes batem com a tabela?
2. Copie `imagem.png` para `imagem.jpg` e escaneie. Por que o veredito é ✅ e não 🟡?
   Você concorda com essa escolha?
3. Por que o motor só lê os primeiros **64 bytes** (`arquivo.cabecalho(64)`) e não o
   arquivo inteiro? O que isso significa para um scan de 10.000 arquivos?
4. A assinatura do BMP é só `BM` (2 bytes). Crie um `carros.txt` com o texto
   `BMW é uma marca de carro` e rode `cabecalho`. O que aconteceu? O veredito
   mudou? Por que assinaturas curtas são perigosas?
5. Desafio: adicione na lista `TIPOS` o formato **ISO** (imagens de CD/DVD), que tem
   `CD001` na posição 32769. Dica: `cabecalho(64)` não vai ser suficiente.

**Próxima aula → Aula 3: Entropia (como detectar conteúdo criptografado ou compactado).**
