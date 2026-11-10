# Aula 6: Hash por semelhança (fuzzy hashing)

## 1. A ideia em uma frase

> E se o hash, em vez de dizer "igual ou diferente", dissesse **"87% parecido"**?

Na Aula 1, o efeito avalanche era uma qualidade (nenhum hash "parecido") e, ao
mesmo tempo, a maior fraqueza do antivírus. O fuzzy hashing faz o contrário de
propósito: **arquivos parecidos geram hashes parecidos**.

```
                     SHA-256 (Aula 1)                      ssdeep (hoje)
  familia-v1.txt ──► a9149c0709c1265e1800902126...         96:Dg2G+qseZ6j57ngiQB9dqtA42QC...
  familia-v2.txt ──► 4ae27b1971f10e8fbe93503770...         96:D52G+KeZ6j57ngiQVNql3CZ0GNP...
                     └─ nada em comum ─┘                   └─ vários pedaços iguais ─┘
                     "diferentes" ❌                        "85% parecidos" ✅
```

O algoritmo mais famoso é o **ssdeep** (2006). Ele é usado pela VirusTotal, por
peritos forenses e por antivírus. Nós usamos o `ppdeep`, uma versão em Python puro.

## 2. Como o ssdeep funciona (a intuição)

### Passo 1: cortar o arquivo em pedaços pelo CONTEÚDO, não pela posição

Se cortássemos a cada 64 bytes fixos, inserir 1 byte no começo deslocaria
**todos** os cortes, e tudo mudaria. O ssdeep corta onde o **conteúdo** manda:
uma janela de 7 bytes desliza pelo arquivo e, quando um cálculo sobre ela dá um
valor especial, ali é um ponto de corte.

```
  corte por posição fixa:                corte pelo conteúdo (ssdeep):
  |aaaa|bbbb|cccc|dddd|                  |aaaa|bbbb|cccc|dddd|
     ▼ insere "X" no começo                 ▼ insere "X" no começo
  |Xaaa|abbb|bccc|cddd|d                 |Xaaaa|bbbb|cccc|dddd|
   ✗    ✗    ✗    ✗   todos mudaram       ✗     ✓    ✓    ✓   só o 1º mudou!
```

Isso se chama *context-triggered piecewise hashing* (CTPH): **hash por pedaços,
disparado pelo contexto**.

### Passo 2: cada pedaço vira UM caractere

```
  arquivo:   [ pedaço 1 ][ pedaço 2 ][ pedaço 3 ][ pedaço 4 ] ...
                  │           │           │           │
               hash fraco  hash fraco  hash fraco  hash fraco
                  ▼           ▼           ▼           ▼
  assinatura:     D           g           2           G       ...  ──► "Dg2G..."
```

### Passo 3: o formato final

```
  96 : Dg2G+qseZ6j57ngiQB9dqtA42QCZ... : vS6NrgHB9d0H2QByE/cljiBnhN2FY
  ▲    ▲                                ▲
  │    pedaços de ~96 bytes              os mesmos pedaços, de ~192 bytes
  tamanho do bloco                       (permite comparar arquivos de tamanhos diferentes)
```

### Passo 4: comparar = quantas "edições" separam as duas assinaturas

```
  v1: Dg2G+qseZ6j57ngiQB9dqtA42QCZ0GNPE1yE/V+L8l3HrKjiBeGh/V2FY
  v2: D52G+K eZ6j57ngiQVNql3   CZ0GNPE1LE/V+L8l3Hr7jiBeGM2F5v
      ✓ ✓✓✓  ✓✓✓✓✓✓✓✓✓✓      ✓✓✓✓✓✓✓ ✓✓✓✓✓✓✓✓✓✓ ✓✓✓✓✓ ✓ ✓
                                                    nota: 85 / 100
```

A nota vem de uma **distância de edição** (quantas inserções, remoções e trocas
transformam uma assinatura na outra), convertida para uma escala de 0 a 100.

## 3. A régua do nosso motor

```
  0 ───────────────────── 50 ─────────────── 80 ──────── 100
  ✅ sem parentesco        🟡 parente         🚨 quase igual
     (no máximo X%)          "72% parecido"     "85% parecido com Familia"
```

E dois limites de tamanho:

| Limite | Por quê |
|---|---|
| **< 4 KB** → não compara | Poucos pedaços: a assinatura fica curta demais e a nota não é confiável (de novo a lição da Aula 3: pouca amostra engana) |
| **> 10 MB** → não compara | O `ppdeep` é Python puro, então arquivos enormes ficariam lentos |

## 4. A família de teste

```
  familia-v1.txt  (10.437 bytes)  ── está na base fuzzy como Teste.SuperAV.Familia
       │
       │  muda ~5% das linhas, apaga 2, acrescenta 1 no fim
       ▼
  familia-v2.txt  (10.352 bytes)  ── NÃO está em base nenhuma
```

E o resultado é o mais bonito do projeto até agora:

```
  python -m superav escanear amostras\teste\familia-v2.txt

  Assinatura (hash)         ✅ passou       ◄── sha256 diferente
  Tipo real (magic bytes)   ✅ passou       ◄── é texto mesmo
  Entropia                  ✅ passou       ◄── 4.04, normal
  Estrutura PE (.exe)       ✅ passou       ◄── não é executável
  Regras YARA               ✅ passou       ◄── nenhuma regra fala dela
  Hash por semelhança       🚨 não passou   85% parecido com Teste.SuperAV.Familia
  ────────────────────────────────────────
  Veredito final: 🚨 MALICIOSO              ◄── só UM motor bastou
```

É a filosofia da Aula 0 funcionando: **o veredito final é o pior entre todos**,
então um único motor especializado pega o que os outros cinco não veem.

## 5. 🔍 Aconteceu na aula: um teste que não testava nada

Meu primeiro teste da faixa 🟡 tinha um `if 50 <= nota < 80:` antes do
`assert`. Quando rodei, a nota deu **100**, e o `if` simplesmente pulou a
verificação. O teste "passou" sem testar coisa alguma. Isso é um **falso verde**,
um dos bugs mais traiçoeiros em testes.

Investigando, descobri o motivo: o texto de teste usava só 13 palavras repetidas.
Com conteúdo tão repetitivo o ssdeep quase não acha pontos de corte, e a nota
pula de **100 direto para 0**:

```
  vocabulário de 13 palavras           letras aleatórias
  troca 20% → 100                       troca 10% → 97
  troca 40% → 100                       troca 30% → 83
  troca 50% → 100                       troca 40% → 79   ◄── cai aos poucos,
  troca 60% →   0  💥 despenca           troca 50% → 72       como deveria
```

A correção foi usar texto mais variado e escrever o teste sem `if`: agora ele
**exige** 🚨, 🟡 e ✅ em três casos fixos (`test_faixas_de_veredito`).

> 💡 Lição de testes: todo `assert` dentro de um `if` merece desconfiança.
> Pergunte "este teste pode falhar?". Se a resposta for "não", ele não está testando.

## 6. Limitações

| Situação | O que acontece |
|---|---|
| Malware **compactado/cifrado** de outro jeito a cada vez | Os bytes mudam inteiros, e a semelhança vai a 0 (por isso existe a entropia, Aula 3) |
| Arquivos muito pequenos | Ignorados (< 4 KB) |
| Muitos arquivos com o mesmo "esqueleto" legítimo | Falso positivo: por exemplo, dois instaladores feitos com a mesma ferramenta podem ser parecidos |
| Base enorme | Comparar com cada assinatura é O(n). Ferramentas reais agrupam por tamanho de bloco para comparar menos |

Existem outros algoritmos de fuzzy hashing, como o **TLSH** (da Trend Micro) e o
**sdhash**, cada um com suas vantagens. O ssdeep é o mais clássico.

## 7. Mão na massa

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# comparar dois arquivos
python -m superav fuzzy amostras\teste\familia-v1.txt amostras\teste\familia-v2.txt

# um arquivo só: compara com a base inteira
python -m superav fuzzy amostras\teste\segredo.txt

# o scan completo
python -m superav escanear amostras --so-ameacas
```

### Ensinando uma família nova ao antivírus

```powershell
python -m superav adicionar-assinatura amostras\limpos\fotos.zip --nome Teste.Minha.Familia --fuzzy
```

Isso grava em `superav/assinaturas/minhas.ssdeep`. Apague esse arquivo depois do exercício.

## 8. Exercícios

1. Copie `familia-v1.txt`, abra a cópia e apague um parágrafo inteiro do meio. Qual a
   nota com `fuzzy`? E o `hash` (SHA-256), mudou quanto?
2. Continue apagando trechos até a nota cair abaixo de 80, e depois abaixo de 50.
   Quanto do arquivo você precisou mudar?
3. Rode `fuzzy` em dois `.docx` diferentes do seu PC. Dá 0%? Por quê? (Dica: o que é um
   `.docx` por dentro, segundo a Aula 2? E qual a entropia de um ZIP, segundo a Aula 3?)
4. Por que o motor exige **4 KB** no mínimo? Rode `fuzzy` no `falso-virus.txt` (160 bytes)
   e olhe o tamanho da assinatura.
5. Desafio: hoje o motor compara com TODAS as assinaturas. Uma comparação ssdeep só faz
   sentido entre assinaturas com o mesmo tamanho de bloco ou com o dobro/metade dele.
   Como você usaria isso para comparar menos (pense num `dict` agrupado por bloco)?

**Próxima aula → Aula 7: Scripts e macros (o último motor do Módulo 1!).**
