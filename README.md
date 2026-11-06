# 🛡️ Super Antivírus

Um antivírus **educacional** em Python que passa cada arquivo por vários motores
de detecção e mostra o que cada um achou:

```
📄 amostras/foto.jpg.exe
   Assinatura (hash)        ✅ passou
   Tipo real (magic bytes)  🚨 não passou  é um .exe disfarçado de .jpg
   Entropia                 🟡 suspeito    7.91 bits/byte
   ...
   Veredito final: 🚨 MALICIOSO
```

Construído uma aula por dia. Veja o [roteiro](ROADMAP.md) e as [aulas](aulas/).

## Como rodar

```bash
# 1. ativar o ambiente virtual (Windows / PowerShell)
.venv\Scripts\Activate.ps1

# 2. instalar dependências (vão sendo adicionadas a cada aula)
pip install -r requirements.txt

# 3. usar
python -m superav motores                     # lista os motores
python -m superav escanear amostras           # escaneia uma pasta
python -m superav escanear arquivo.exe --motores hash,yara
python -m superav hash arquivo.exe              # mostra MD5, SHA-1 e SHA-256
python -m superav cabecalho arquivo.exe         # mostra os primeiros bytes e o tipo real
python -m superav entropia arquivo.exe          # gráfico de entropia, trecho por trecho
python -m superav adicionar-assinatura arquivo.exe --nome Nome.Da.Ameaca
python -m superav escanear C:\Users\voce\Downloads --so-ameacas

# 4. testes
python -m unittest discover tests
```

## Estrutura

```
super-antivirus/
├── superav/
│   ├── core/            ← o núcleo (não muda quando entra motor novo)
│   │   ├── motor.py     ← contrato: Motor, Arquivo, Resultado, Veredito
│   │   ├── registro.py  ← lista de chamada dos motores (@registrar)
│   │   ├── scanner.py   ← passa cada arquivo por todos os motores
│   │   └── relatorio.py ← imprime o resultado
│   ├── motores/         ← um arquivo por motor; criou, já funciona
│   └── cli.py           ← linha de comando
├── tests/               ← testes automáticos
├── aulas/               ← material de cada aula
└── amostras/            ← arquivos de teste (só limpos/ vai pro git)
```

> ⚠️ Projeto de estudo. Não substitui um antivírus de verdade.
