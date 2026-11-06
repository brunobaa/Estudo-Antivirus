# Aula 3: Entropia

## 1. A ideia em uma frase

> Dados com significado são **previsíveis**. Dados criptografados ou compactados parecem **ruído**.

A entropia mede essa "cara de ruído", sem precisar entender o conteúdo.

```
  texto em português:          dados criptografados:
  "a casa da avó..."           7F A2 0B E9 33 C1 5D 88 ...

  frequência de cada byte      frequência de cada byte
   █                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █ █                          ████████████████████████
   █ █   █                      ████████████████████████
  ─┴─┴─┴─┴───────────          ─┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴─
   a e ␣ o  (poucos dominam)     0 ...................255
                                 (todos aparecem igual)
  entropia ≈ 4.3                entropia ≈ 8.0
```

## 2. Entropia = "surpresa média"

Claude Shannon criou essa medida em 1948, na teoria da informação (a mesma base
das redes de computadores que você estuda).

- Se um byte é **muito comum**, vê-lo não surpreende → pouca informação.
- Se um byte é **raro**, vê-lo surpreende → muita informação.

```
  H = - Σ p(x) · log₂ p(x)          p(x) = quantas vezes o byte x aparece / total
```

### Calculando na mão: "AAAB"

```
  bytes:  A A A B         p(A) = 3/4 = 0.75     p(B) = 1/4 = 0.25

  A:  -0.75 × log₂(0.75) = -0.75 × (-0.415) = 0.311
  B:  -0.25 × log₂(0.25) = -0.25 × (-2.000) = 0.500
                                              ─────
                                        H  =  0.811 bits/byte
```

### A régua de 0 a 8

```
  "AAAAAAAA"    "ABABABAB"   "ABCD"      texto     programa   compactado
     │             │           │           │          │       criptografado
     ▼             ▼           ▼           ▼          ▼            ▼
  0 ─┼─────────────┼───────────┼───────────┼──────────┼──────┬─────┼─ 8
     0.0           1.0         2.0        ~4.3       ~5-6   7.2   ~8.0
                                                             │
                                                    a partir daqui:
                                                   "parece aleatório"
```

- **8 é o máximo** porque um byte tem 8 bits (256 valores possíveis, e log₂(256) = 8).
- Com só 2 valores diferentes, o máximo é log₂(2) = **1**. Com 4, é log₂(4) = **2**.

Todos esses números estão provados em `tests/test_entropia.py`.

## 3. Por que compactado e criptografado dão ~8

```
  COMPACTAR = tirar a repetição
  "aaaaaaaaaabbbbb"  ──zip──►  "10×a 5×b"   ◄── sobra só o "imprevisível"

  CRIPTOGRAFAR = esconder qualquer padrão
  "ola mundo"  ──AES──►  7F A2 0B E9 33 C1 ...   ◄── se sobrasse padrão,
                                                     daria para quebrar a cifra
```

Nos dois casos o resultado parece ruído. Isso é **normal** num `.zip`, `.jpg`,
`.mp4` ou `.png`, que já são formatos compactados. Mas levanta suspeita em dois casos:

### Suspeita 1: executável empacotado (packer)

```
  executável normal                      executável empacotado (ex: UPX, ou pior)
  ┌───────────────────────────┐          ┌───────────────────────────┐
  │ cabeçalho        H ≈ 2    │          │ cabeçalho        H ≈ 2    │
  │ código (.text)   H ≈ 6    │          │ mini "descompactador"     │
  │ dados  (.data)   H ≈ 4    │          │ ███ código CIFRADO ███    │ H ≈ 8
  │ ícone  (.rsrc)   H ≈ 7.5  │          │ ███  ███  ███  ███  ███   │
  └───────────────────────────┘          └───────────────────────────┘
   alguns trechos altos (o ícone)         QUASE TUDO alto
   ✅ normal                              🟡 o código real está escondido
```

Malwares usam packers para que o código verdadeiro só apareça **na memória**,
depois de executar. No disco, o antivírus só vê ruído e nenhuma assinatura funciona.

### Suspeita 2: arquivo sequestrado (ransomware)

```
  antes:   relatorio.txt   H = 4.3   "Prezados, segue o relatório..."
               │
               │  ransomware criptografa
               ▼
  depois:  relatorio.txt   H = 7.98  7F A2 0B E9 33 C1 5D ...   ◄── 🟡 um .txt NÃO
                                                                    deveria ser ruído
```

Antivírus modernos usam isso **em tempo real**: se um processo começa a
transformar dezenas de arquivos de baixa entropia em alta entropia, ele é
interrompido. (Vamos chegar perto disso na Aula 9, a de tempo real.)

## 4. Contexto é tudo: a árvore do motor

```
                    arquivo < 512 bytes?
                   ┌────────┴────────┐
                  SIM               NÃO
                   ▼                 ▼
          ✅ pequeno demais    tipo real (usa o motor da Aula 2!)
                          ┌──────────┼─────────────────┐
                    compactado/   executável       texto/outro
                  imagem/mídia        │                 │
                       ▼              ▼                 ▼
                  ✅ normal      ≥ 50% dos trechos   geral ≥ 7.2?
                  para ZIP       com H ≥ 7.2?       ┌────┴────┐
                                 ┌────┴────┐       SIM       NÃO
                                SIM       NÃO       ▼         ▼
                                 ▼         ▼    🟡 parece   ✅ passou
                            🟡 packer?  ✅ normal  criptografado
```

O motor **reaproveita** o `identificar()` da Aula 2. Um motor sozinho é limitado,
mas juntos eles ficam muito mais espertos.

## 5. Por que medir por trechos (blocos de 4 KB)

A entropia **geral** pode esconder um trecho perigoso no meio de muita coisa normal:

```
  python -m superav entropia amostras\teste\empacotado.exe

  posição        entropia por trecho          (0 ─── 4 ─── 7.2 ─ 8)
           0  ████████████████████████████████ 7.93  ◄ parece aleatório
       4,096  ████████████████████████████████ 7.95  ◄ parece aleatório
         ...
      24,576  ███████████████████████░░░░░░░░░ 5.78   ◄── último pedaço, pequeno
```

## 6. Pegadinha: pouca amostra, entropia menor

Medi bytes **100% aleatórios**, mudando só a quantidade:

```
     64 bytes  ███████████████████████░░░░░░░░░ 5.80
    256 bytes  █████████████████████████████░░░ 7.22
  1.024 bytes  ███████████████████████████████░ 7.83
  4.096 bytes  ████████████████████████████████ 7.96
 65.536 bytes  ████████████████████████████████ 8.00
```

Com 64 bytes é **impossível** aparecerem os 256 valores diferentes, então a
entropia sai baixa mesmo sendo puro ruído. Por isso:

- o motor **ignora arquivos com menos de 512 bytes** (seriam medidas mentirosas);
- o último trecho de um arquivo quase sempre aparece mais baixo no gráfico.

Esse erro apareceu de verdade num teste durante a aula, e a correção está
comentada em `test_medir_soma_blocos`.

## 7. As limitações (e como os atacantes fogem)

| Truque do atacante | Efeito na entropia |
|---|---|
| Codificar em **Base64** | Só 64 símbolos → máximo log₂(64) = **6.0** (teste `test_base64_nunca_passa_de_6`) |
| Misturar com muitos dados "normais" (padding) | A geral cai; os blocos ainda denunciam |
| Usar um packer comercial legítimo | Programas honestos também usam: falso positivo |

Por isso a entropia gera **🟡 suspeito**, nunca 🚨 sozinha. É um **indício**, não uma prova.

## 8. Mão na massa

```powershell
.venv\Scripts\Activate.ps1

# o gráfico de entropia, trecho por trecho
python -m superav entropia amostras\teste\empacotado.exe
python -m superav entropia amostras\limpos\texto-longo.txt
python -m superav entropia amostras\limpos\fotos.zip

# os três motores juntos, só mostrando ameaças
python -m superav escanear amostras --so-ameacas
```

## 9. Exercícios

1. Calcule na mão a entropia de `"AABB"` e de `"AAAAAAAB"`. Confira com Python:
   `python -c "from superav.motores.entropia import entropia; print(entropia(b'AABB'))"`
2. Rode `entropia` num programa de verdade, por exemplo `C:\Windows\System32\notepad.exe`.
   Onde ficam os trechos mais altos? (Dica: ícones e imagens ficam no final.)
3. Compacte o `texto-longo.txt` num ZIP pelo Windows e rode `entropia` no ZIP. Quanto subiu?
4. Por que um `segredo.txt` com 7.98 é 🟡 suspeito, mas o `fotos.zip` com 7.97 é ✅?
   Que motor da aula passada tornou essa diferença possível?
5. Desafio: um ransomware esperto poderia criptografar só **os primeiros 4 KB** de cada
   arquivo (é mais rápido e já estraga o arquivo). O nosso motor pegaria? Como você
   mudaria o motor para pegar esse caso?

**Próxima aula → Aula 4: Estrutura de executáveis do Windows (PE).**
