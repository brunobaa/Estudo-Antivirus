# Aula 7: Scripts e macros (e o fechamento do Módulo 1)

## 1. A ideia em uma frase

> Um script não precisa ser um programa estranho: ele usa os programas que o
> próprio Windows já tem. Então o antivírus precisa ler o **texto** e perguntar
> o que ele pede e como ele se esconde.

```
  executável (.exe)                       script (.ps1, .js, .vbs, .bat, .hta)
  ┌─────────────────────────┐             ┌─────────────────────────┐
  │ MZ, seções, imports     │             │ é só TEXTO              │
  │ → motor PE (Aula 4)     │             │ sem cabeçalho, sem      │
  │                         │             │ imports, entropia baixa │
  └─────────────────────────┘             └───────────┬─────────────┘
                                                      │ quem executa?
                                                      ▼
                                   powershell.exe, wscript.exe, mshta.exe, cmd.exe
                                   (programas LEGÍTIMOS que já vêm no Windows)
```

Atacantes adoram isso. Na área de segurança, usar as ferramentas do próprio
sistema contra ele tem nome: ***living off the land*** ("viver da terra").

## 2. As duas perguntas do motor

```
                              script.ps1
                                  │
              ┌───────────────────┴───────────────────┐
              ▼                                       ▼
      1. O QUE ele usa?                      2. COMO está escrito?
  ┌───────────────────────────┐          ┌───────────────────────────┐
  │ executar texto como código│          │ bloco Base64 gigante      │
  │ conteúdo codificado       │          │ texto picotado: "a"+"b"+…  │
  │ janela escondida          │          │ caracteres por código     │
  │ download da internet      │          │ crases: In`vo`ke          │
  │ objetos de sistema        │          │ circunflexos: e^c^h^o     │
  └─────────────┬─────────────┘          │ linhas de 1000+ caracteres│
                │                        └─────────────┬─────────────┘
                └──────────────┬───────────────────────┘
                               ▼
                    soma dos pontos (mesma régua da Aula 4)
         0 ───────────── 3 ──────────── 6 ──────────►
         ✅ normal       🟡 suspeito     🚨 vários sinais juntos
```

### Por que ofuscação é um sinal tão forte

Programador honesto quer código **legível**. Ninguém escreve ``W`r`i`t`e-H`o`s`t``
de propósito, a não ser para enganar quem lê (ou para enganar um antivírus que
procura a palavra `Write-Host`):

```
  o que o atacante escreve:     W`r`i`t`e-H`o`s`t
  o que o PowerShell executa:   Write-Host            ◄── a crase é ignorada
  o que um filtro ingênuo vê:   nada de "Write-Host"  ◄── escapou!
  o que o nosso motor vê:       7 crases no meio de palavras 🟡
```

É a mesma lição de todo o módulo: quando o atacante se esforça para se
**esconder**, o próprio esconderijo vira o sinal.

### A combinação vale mais que as partes

```
  só baixar da internet          → atualizador, instalador...       (normal)
  só executar texto como código  → ferramentas de automação...      (normal)
  baixar E executar na hora      → padrão clássico de ataque  +2 extra
```

## 3. Detalhes técnicos que apareceram

### Scripts do Windows muitas vezes estão em UTF-16

```
  "invoke" em UTF-8:    69 6E 76 6F 6B 65
  "invoke" em UTF-16:   69 00 6E 00 76 00 6F 00 6B 00 65 00   ◄── um zero entre cada letra
```

Procurando direto nos bytes, o motor não acharia nada. Por isso `decodificar()`
detecta o BOM (`FF FE`), ou a presença de muitos zeros, e converte antes de procurar.

### Palavra inteira x pedaço de palavra

`iex` é o apelido de `Invoke-Expression`, mas aparece **dentro** de outras
palavras, como `iexplore.exe` (o Internet Explorer). Termos curtos são procurados
como **palavra inteira**, depois de separar o texto em palavras.

## 4. 🔍 Aconteceu na aula: dois bugs, dois aprendizados

**Bug 1: no teste.** Eu queria provar que "iex" dentro de outra palavra não conta,
e escrevi a frase: *"a palavra complex contem **iex** dentro"*. A frase tinha
"iex" como palavra solta! O motor acertou e o teste estava errado. Pior ainda:
na primeira correção eu usei "complex", que nem contém "iex". Agora o teste usa
`iexplore.exe`, um exemplo real.

**Bug 2: no motor.** Para contar as crases de ``W`r`i`t`e``, eu usei a expressão
``[a-z]`[a-z]``. Só que o `findall` **não conta pedaços sobrepostos**:

```
  W ` r ` i ` t ` e
  └─┬─┘              casou "W`r"
      ✗              "r`i" não conta: o "r" já foi usado
        └─┬─┘        casou "i`t"
            ✗        "t`e" não conta: o "t" já foi usado
  resultado: 2 em vez de 4 💥
```

A correção é um ***lookahead***, ``[a-z]`(?=[a-z])``: o `(?=...)` **confere** a letra
seguinte sem **consumi-la**, então ela pode ser o começo do próximo par.

## 5. Mão na massa

```powershell
.venv\Scripts\Activate.ps1

# cada indício, com os pontos de cada um
python -m superav script amostras\teste\ofuscado.js
python -m superav script amostras\limpos\ola.ps1

# os 7 motores juntos
python -m superav escanear amostras --so-ameacas
```

A amostra `ofuscado.js` imita o **jeito** de um script ofuscado (Base64,
`fromCharCode`, `eval`), mas só monta e mostra a frase "ola, SuperAV". Ela não
baixa nada e não toca em nenhum arquivo.

## 6. Exercícios

1. Rode `script` nos scripts `.ps1` que existem no seu PC
   (`C:\Windows\System32\WindowsPowerShell\v1.0\Modules` tem vários). Algum pontua? Por quê?
2. Por que `-noprofile` vale só 1 ponto e `-encodedcommand` vale 3?
3. Crie um `.ps1` com ``W`r`i`t`e-H`o`s`t "oi"``, rode no PowerShell (ele funciona!) e
   depois rode `script` nele.
4. Salve um `.ps1` em UTF-16 (no Bloco de Notas: Salvar como → Codificação UTF-16 LE) e
   rode `cabecalho` nele. Você vê o `FF FE` e os zeros?
5. Desafio: macros VBA dentro de `.docm`/`.xlsm` (formato novo, que é ZIP!) não são
   pegas pela regra YARA da Aula 5, que só olha o formato OLE antigo. Pesquise a
   ferramenta `olevba` (pacote `oletools`) e pense em como ela viraria um motor.

---

# 🎓 Fechamento do Módulo 1: Detecção em arquivos

## Os 7 motores

```
                                   arquivo
     ┌──────────┬──────────┬──────────┼──────────┬──────────┬──────────┐
     ▼          ▼          ▼          ▼          ▼          ▼          ▼
  ┌──────┐  ┌──────┐  ┌────────┐  ┌──────┐  ┌──────┐  ┌───────┐  ┌────────┐
  │ Hash │  │ Tipo │  │Entropia│  │  PE  │  │ YARA │  │ Fuzzy │  │Scripts │
  │  A1  │  │  A2  │  │   A3   │  │  A4  │  │  A5  │  │  A6   │  │   A7   │
  └──┬───┘  └──┬───┘  └───┬────┘  └──┬───┘  └──┬───┘  └───┬───┘  └───┬────┘
     │"já vi   │"é o que  │"parece   │"o que    │"tem esse │"é parente │"o que
     │ igual?" │ diz ser?"│ cifrado?"│ pretende │ padrão?" │ de algo   │ pede e
     │         │          │          │ fazer?"  │          │ ruim?"    │ como se
     ▼         ▼          ▼          ▼          ▼          ▼           esconde?"
     └─────────┴──────────┴──────────┴────┬─────┴──────────┴───────────┘
                                          ▼
                           veredito final = o PIOR deles
```

## O que cada um pega que os outros perdem

| Motor | Pega | Deixa passar |
|---|---|---|
| Hash | cópia exata de malware conhecido | qualquer variação de 1 byte |
| Tipo | disfarce (.pdf que é .exe, RLO) | malware sem disfarce |
| Entropia | conteúdo cifrado/empacotado | malware em texto puro |
| PE | intenção (injeção, keylogger) | scripts e documentos |
| YARA | famílias por padrões | o que nenhuma regra descreve |
| Fuzzy | variantes parecidas | malware muito alterado |
| Scripts | ofuscação e abuso de ferramentas do sistema | executáveis |

**Nenhum é suficiente sozinho, e juntos cobrem uns aos outros.** Esse é o
princípio de **defesa em profundidade**, o mesmo que você vê em redes: firewall,
IDS e criptografia, cada um numa camada.

## As lições que apareceram de verdade no caminho

```
  Aula 2  caractere invisível RLO entrou no NOSSO código     → revisar o que é invisível
  Aula 3  pouca amostra subestima a entropia                 → limites mínimos de tamanho
  Aula 4  kernel32.dll acusada                               → falso positivo e allowlist
  Aula 5  YARA em C não abre "Área de Trabalho"              → testes de regressão
  Aula 6  teste com "if" que nunca testava                   → desconfiar de falso verde
  Aula 7  findall pulando pares sobrepostos                  → lookahead em regex
```

**Próximo módulo → Módulo 2: Proteção ativa**, começando pela **Aula 8: Quarentena**.
Até aqui o antivírus só **avisa**; a partir de agora ele começa a **agir**.
