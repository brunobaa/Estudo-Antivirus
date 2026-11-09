/*
    Regras YARA do Super Antivírus (Aula 5)
    ----------------------------------------
    Toda regra tem 3 partes:

        meta:       informações sobre a regra (não afetam a detecção)
        strings:    os padrões que procuramos (texto, hexadecimal, regex)
        condition:  a lógica que decide se a regra "casou"

    O motor lê o campo meta "severidade":
        "malicioso" -> 🚨 não passou
        "suspeito"  -> 🟡 suspeito   (padrão, se a regra não disser nada)

    Todo arquivo .yar desta pasta é carregado automaticamente.
*/

rule SuperAV_FalsoVirus
{
    meta:
        descricao  = "Nosso falso vírus de teste, mesmo se alguém mudar alguns bytes"
        severidade = "malicioso"
        aula       = 5

    strings:
        $nome   = "Teste.SuperAV.FalsoVirus"
        $aviso  = "INOFENSIVO" nocase
        $motor  = "motor de hash do Super Antivirus"

    condition:
        // Basta 2 dos 3 trechos: pega variantes que o hash (Aula 1) deixaria passar
        2 of them
}

rule EICAR_Arquivo_De_Teste
{
    meta:
        descricao  = "Arquivo de teste padrão da indústria (eicar.org)"
        severidade = "malicioso"
        aula       = 5

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar and filesize < 256
}

rule Nota_De_Resgate
{
    meta:
        descricao  = "Texto típico de nota de resgate de ransomware"
        severidade = "malicioso"
        aula       = 5

    strings:
        $pt1 = "seus arquivos foram criptografados" nocase
        $pt2 = "pagar o resgate" nocase
        $en1 = "your files have been encrypted" nocase
        $en2 = "pay the ransom" nocase
        $btc = "bitcoin" nocase
        $tor = ".onion" nocase
        $chave = "chave de descriptografia" nocase

    condition:
        // Uma frase solta pode aparecer num artigo; 3 juntas é bem mais raro
        3 of them
}

rule Executavel_Pequeno_Demais
{
    meta:
        descricao  = "Começa com MZ mas é pequeno demais para ser um programa de verdade"
        severidade = "suspeito"
        aula       = 5

    condition:
        // uint16(0) lê 2 bytes na posição 0. "MZ" em little-endian = 0x5A4D
        uint16(0) == 0x5A4D and filesize < 1KB
}

rule Documento_Office_Com_Macro_Automatica
{
    meta:
        descricao  = "Documento Office antigo com macro que roda sozinha ao abrir"
        severidade = "suspeito"
        aula       = 5

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }   // magic bytes do OLE2 (Aula 2)
        $a1  = "AutoOpen" nocase
        $a2  = "Document_Open" nocase
        $a3  = "Workbook_Open" nocase
        $a4  = "Auto_Open" nocase

    condition:
        $ole at 0 and any of ($a*)
}
