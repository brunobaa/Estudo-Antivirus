# Aula 5: Regras YARA

## 1. A ideia em uma frase

> O hash pergunta "é **este** arquivo?". O YARA pergunta "este arquivo **tem cara de**...?"

YARA foi criado em 2008 por Victor Alvarez, na VirusTotal, e virou o **idioma
padrão** da indústria para descrever malware. Pesquisadores publicam regras YARA
em relatórios de ameaças, e praticamente todo antivírus e ferramenta de
análise consegue lê-las.

```
  HASH (Aula 1)                         YARA (hoje)
  ┌──────────────────────────┐          ┌──────────────────────────────┐
  │ abb4e44c...  == exato?   │          │ tem "Teste.SuperAV" ?        │
  │                          │          │ tem "INOFENSIVO" ?           │
  │ 1 byte diferente         │          │ pelo menos 2 desses?         │
  │ → não reconhece mais 😱  │          │ → reconhece a família toda ✅│
  └──────────────────────────┘          └──────────────────────────────┘
```

## 2. A anatomia de uma regra

```yara
rule Nota_De_Resgate                       ◄── nome (sem espaços)
{
    meta:                                  ◄── 1. informações (não mudam a detecção)
        descricao  = "Texto típico de nota de resgate de ransomware"
        severidade = "malicioso"           ◄── o NOSSO motor lê este campo

    strings:                               ◄── 2. o que procurar
        $pt1 = "seus arquivos foram criptografados" nocase
        $btc = "bitcoin" nocase
        ...

    condition:                             ◄── 3. a lógica final
        3 of them
}
```

### Os 3 tipos de string

```
  texto       $a = "bitcoin"               procura exatamente esse texto
  texto+opção $a = "bitcoin" nocase        ignora maiúsculas/minúsculas
  hexadecimal $h = { D0 CF 11 E0 A1 B1 }   procura bytes (magic bytes da Aula 2!)
  regex       $r = /[a-z2-7]{16}\.onion/   expressão regular
```

### Condições: onde mora a inteligência

```
  $a                      a string $a aparece
  $a and $b               as duas aparecem
  2 of them               pelo menos 2 das strings da regra
  any of ($a*)            qualquer string cujo nome começa com $a
  $ole at 0               $ole está exatamente no byte 0
  filesize < 1KB          o arquivo tem menos de 1 KB
  uint16(0) == 0x5A4D     os 2 primeiros bytes são "MZ" (lidos ao contrário!)
```

> 💡 Por que `0x5A4D` e não `0x4D5A`? O x86 guarda números com o byte menos
> significativo primeiro (**little-endian**). "M"=4D e "Z"=5A, lidos como número
> de 16 bits, viram 0x5A4D. Mesma ideia da ordem dos bytes em redes, só que ao
> contrário: em redes o padrão é big-endian.

## 3. As nossas 5 regras

| Regra | O que procura | Severidade |
|---|---|---|
| `SuperAV_FalsoVirus` | 2 de 3 trechos do falso vírus | 🚨 |
| `EICAR_Arquivo_De_Teste` | texto do EICAR em arquivo pequeno | 🚨 |
| `Nota_De_Resgate` | 3+ frases típicas de ransomware (pt e en) | 🚨 |
| `Executavel_Pequeno_Demais` | começa com MZ e tem menos de 1 KB | 🟡 |
| `Documento_Office_Com_Macro_Automatica` | OLE2 no byte 0 + `AutoOpen`/`Document_Open` | 🟡 |

## 4. Como o motor funciona

```
  superav/regras/*.yar
  ┌──────────────────┐   Python lê o texto    ┌─────────────────┐
  │ superav.yar      │ ─────────────────────► │ yara.compile()  │  uma vez só,
  │ (suas_regras.yar)│   sources={...}        │                 │  no início
  └──────────────────┘                        └────────┬────────┘
                                                       │ regras compiladas
  para cada arquivo:                                   ▼
  arquivo.dados ──────────────────────────────► regras.match()
                                                       │
                              ┌────────────────────────┼─────────────────┐
                         nenhuma casou           casou "suspeito"   casou "malicioso"
                              ▼                        ▼                 ▼
                          ✅ passou               🟡 suspeito       🚨 não passou
                                         (vale a PIOR severidade entre as que casaram)
```

O YARA **compila** as regras antes, como um programa: transforma todas as strings
numa estrutura de busca (algoritmo de Aho-Corasick) que procura **todas ao mesmo
tempo**, numa única passada pelo arquivo. Por isso ele aguenta milhares de regras.

## 5. A lição principal: YARA pega o que o hash perde

```
  falso-virus.txt            ──► hash 🚨 conhecido   YARA 🚨 2 de 3 trechos
       │ + 1 espaço no final
       ▼
  variante.txt               ──► hash ✅ desconhecido  YARA 🚨 2 de 3 trechos  ◄── 🎯
```

Isso está provado no teste `test_yara_pega_variante_que_o_hash_perde`.

## 6. Escrever regra boa é uma arte: falsos positivos de novo

```
  regra fraca:    $btc = "bitcoin"           condition: $btc
                  → toda notícia sobre bitcoin vira ransomware 😠

  nossa regra:    7 frases típicas           condition: 3 of them
                  → precisa de VÁRIOS sinais juntos ✅
```

O teste `test_nota_de_resgate_precisa_de_3_frases` garante que uma notícia
comum sobre bitcoin **não** é acusada.

## 7. 🔍 Aconteceu na aula: o bug do acento

Na primeira execução, o motor quebrou com:

```
  yara.Error: (2, 'No such file or directory')
```

O arquivo existia! O problema é que a biblioteca YARA é escrita em **C** e, no
Windows, não abre caminhos com acento, como o seu "**Á**rea de Trabalho". O teste
rápido que eu tinha feito antes funcionou só porque usava um caminho relativo,
sem acento.

```
  antes:   yara.compile(filepaths={"superav": "C:\...\Área de Trabalho\...\superav.yar"})
                                                     ▲ C não entende 💥
  depois:  texto = Python lê o arquivo (Python entende acentos)
           yara.compile(sources={"superav": texto})   ◄── YARA só recebe o texto ✅
```

Agora existe um teste de regressão, `test_caminho_com_acento`, para esse bug nunca voltar.

## 8. Robustez

- **Regra com erro de sintaxe** → o motor responde ❌ erro com a mensagem, e os outros
  motores continuam (teste `test_regra_quebrada_vira_erro_e_nao_derruba`).
- **`timeout=10`** → um arquivo gigante ou uma regra muito pesada não trava o scan.
- **Sem `yara-python` instalado** → o motor fica ⏳ pendente.

## 9. Mão na massa

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# ver QUAIS regras casaram e ONDE no arquivo
python -m superav yara amostras\teste\nota-de-resgate.txt
python -m superav yara amostras\teste\boleto.pdf

# scan completo com os 5 motores
python -m superav escanear amostras --so-ameacas
```

### Criando sua própria regra

Crie `superav/regras/minhas.yar` (todo `.yar` da pasta é carregado sozinho):

```yara
rule Minha_Primeira_Regra
{
    meta:
        descricao  = "Acha arquivos que falam de Redes"
        severidade = "suspeito"
    strings:
        $a = "protocolo" nocase
        $b = "pacote" nocase
    condition:
        $a and $b
}
```

## 10. Exercícios

1. Escreva a regra acima, crie um `.txt` que case com ela e rode `yara` nele.
   Depois apague o `.yar` (é só um exercício).
2. Na regra `SuperAV_FalsoVirus`, troque `2 of them` por `all of them`. A variante
   com 1 espaço a mais ainda é pega? E se você apagar a palavra "INOFENSIVO"?
3. Por que a regra do EICAR tem `filesize < 256`? O que aconteceria sem isso com,
   por exemplo, um artigo sobre antivírus que cita o nome do arquivo EICAR?
4. Explique, com suas palavras, por que `uint16(0) == 0x5A4D` significa "começa com MZ".
5. Desafio: o arquivo `amostras/teste/empacotado.exe` não casa com nenhuma regra.
   Escreva uma regra que pegue executáveis (MZ no início) **maiores** que 1 KB que
   não tenham a palavra `This program cannot be run in DOS mode`, frase que quase
   todo `.exe` legítimo tem. Dica: `not $frase`.

**Próxima aula → Aula 6: Hash por semelhança (fuzzy hashing).**
