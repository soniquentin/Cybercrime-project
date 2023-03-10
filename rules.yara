import "hash"
import "pe"


rule match_sample{
     condition:
        pe.is_pe and pe.DLL and hash.sha256(0,filesize) == "5ffecf27b187bcaec80b45b570631e5bd53672b23dedb4d28d4e3dc6e81214b1"
}


rule similar_samples {
   meta:
      hash1 = "5ffecf27b187bcaec80b45b570631e5bd53672b23dedb4d28d4e3dc6e81214b1"
   strings:
      $s1 = "Hatazuyi jubok yib. Tumajuso ninitofu lekixig vabisip. Wocodatepogovi musorojip yinipoxewibu kicaciruvi wafuwonaliy. Fawiturizor" ascii
      $s2 = "C:\\zos-laxuloyin\\pokina57-nazodaje85\\xix.pdb" fullword ascii
      $s3 = "oxu. Torunokemice. Jevujabebiw. Duroyi tinevoweme. Monenelovo xin. Debomupip duculepahe. Vice kiduyugukey gigaceyeden. Rafazikac" ascii
      $s4 = "FFDDDD" ascii /* reversed goodware string 'DDDDFF' */
      $s5 = "yepuxohefovubarenoviwedulenenomoyukoreyeruwilejo" fullword wide
      $s6 = "Af:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\dbgdel.cpp" fullword wide
      $s7 = "P(\"Invalid file descriptor. File possibly closed by a different thread\",0)" fullword wide
      $s8 = "(\"_Dest_size >= (size_t)(_Last - _First)\", 0)" fullword wide
      $s9 = "ez. Tovuboy. Conudosuruyiyit zisuri fewu logevacemo cucufaxojevo. Jadedohilupaho bopoz sXebemut negamirisiniroy regavixutalunu x" ascii
      $s10 = " Type Descriptor'" fullword ascii
      $s11 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\include\\streambuf" fullword ascii
      $s12 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\include\\xdebug" fullword ascii
      $s13 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\include\\xiosbase" fullword ascii
      $s14 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\include\\xstring" fullword wide
      $s15 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\feoferr.c" fullword wide
      $s16 = "SovositebesayawYLitoh zeremofimo dukugenibiloyun pavi binomem rah voyepatezosoxa ledegabarun copivilupepu" fullword wide
      $s17 = "555:5?5\\6" fullword ascii /* hex encoded string 'UUV' */
      $s18 = "?.?3?8?=?" fullword ascii /* hex encoded string '8' */
      $s19 = "Sibafanenowiku xilagok. Zuwab. Mezatuwu tebuget mulapohakil. Faze dosizuw zohofajovuy kevogi. Cuzehogoc vis ricitow bab momumoli" ascii
      $s20 = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\include\\xlocale" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 8 of them
}


rule same_rich_header {
     condition:
        pe.rich_signature.raw_data == "\xda\xba\x81\xf9\x9e\xdb\xef\xaa\x9e\xdb\xef\xaa\x9e\xdb\xef\xaa#\x94y\xaa\x9f\xdb\xef\xaa\x80\x89z\xaa\x8f\xdb\xef\xaa\x80\x89l\xaa\xe7\xdb\xef\xaa\xb9\x1d\x94\xaa\x99\xdb\xef\xaa\x9e\xdb\xee\xaaN\xdb\xef\xaa\x80\x89k\xaa\xdf\xdb\xef\xaa\x80\x89{\xaa\x9f\xdb\xef\xaa\x80\x89~\xaa\x9f\xdb\xef\xaa"
}
