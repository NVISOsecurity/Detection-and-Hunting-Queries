# Shady Panda Suspicious Browser Extensions

## Description

Detects the presence of browser extensions associated with the ShadyPanda campaign infecting 4.3 million users. Extensions presented themselves as productivity tools such as new tab pages, translators, or tab managers, while operating as spyware. Additional research uncovered additional extensions connected to the same infrastructure, adding 1.3 million more victims. The queries detects suspicious extensions related to the Shady Panda campaign.

## References

- https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers#heading-3

## Queries

### <Defender for Endpoint>

If you have Microsoft Defender Vulnerability Management run:

```KQL
let extension_ids = dynamic([
"aikflfpejipbpjdlfabpgclhblkpaafo",
"dbfmnekepjoapopniengjbcpnbljalfg",
"nnnkddnnlpamobajfibfdgfnbcnkgngh",
"ppfdcmempdfjnanjegmjhanplgjicefg",
"fmiefmaepcnjahoajkfckenfngfehhma",
"edojphplonjclmfckdiolpahpgcanjnh",
"bjehnpiidogpaocjjfhnopdjcahigggm",
"kdgjiakonpbfmndaacfhamdoangincgp",
"dihekmadkkcgnffajefocfamnpimlhah",
"eijnkinhnplaekpllmgbbfieecdhcmcp",
"mdlkdelnchilkeedllnnjfigkhhadlff",
"agepkkdokhlaoiaenedmjbfnblfdiboc",
"epepbcdeelckgplpmmmnmjplbeipgllo",
"makeekhnfplggoaiklkphfopajegajci",
"cahdpfhnokmnnjhoaoliabdbcbbokmgc",
"mmpfmolbdhdfoblfggigchncdgmdnjha",
"knejepegjmjmjlhficbikmblnbemdpke",
"cjlabngphhjjdapemkdnpgkpebkpjbbe",
"jeaebbdndojkbnnfcaihgokhnakocbnf",
"bajoeadpdidoahbhphmhejmbdmgnbdci",
"goiffchdhlcehhgdpdbocefkohlhmlom",
"djkddblnfgendjoklmfmocaboelkmdkm",
"codgofkgobbmgglciccjabipdlgefnch",
"cicnbbdlbjaoioilpbdioeeaockgbhfi",
"mchacgmgddefeohkjobefhihbadocneh",
"oelcnhfgpdjeocflhhfecinnpjojeokp",
"fllcifcfhgmmfpogmpedgbjccnjalpjo",
"fmgaogkbodhdhhbgkphhbokciiecllno",
"dkbpkjhegfanacodkmfjeackckmehkfp",
"jooiimddfkjoomennmpjabdbbpdocjng",
"dekjibpkbhgbnmnfibnibnjoccaphfog",
"mnamhmcgcfflfjafflanbhbfffpmkmmm",
"ambcheakfbokmebglefpbbphbccekhhl",
"nmaegedpdmepbkahckadmaolllgmogma",
"doeomodlafdbbnajjllemacdfphbbohl",
"meobjhkdifjealkiaanikkpajiaalcad",
"kfdopiiledmclnopmihkclnfgdiggjna",
"cfgiodgnkinmacjkgjgdejeciohojglp",
"okepehobneenpbhiendcjcanjodhmcbj",
"cdgonefipacceedbkflolomdegncceid",
"bgkdocoihppjkdfaghndpjlfoehjcmka",
"ldmnodpmebcfcdkejkdakphbcjnmejlf",
"pdfladlchakneeclhmpoboohikpbchkj",
"gipnpcencdgljnaecpekokmpgnhgpela",
"idholfkkmfccbondfiabhlmdfeamnnaj",
"bpgaffohfacaamplbbojgbiicfgedmoi",
"jdehnhjckcbfdkgnlbfjokofagpbbdgl",
"dijcdmefkmlhnbkcejcmepheakikgpdg",
"gndlcpbcmhbcaadppjjekgbhfhceeikm",
"lepdjbhbkpfenckechpdfohdmkhogojf",
"hbjeophpjnopmeheabcilmgdhnnjbmbo",
"dlfjoijnhjeagkenhbililbdiooginng",
"kolgdodmgnnhnijmnnidfabnghgakobl",
"edohfgmjmdnibeihfcajfclmhapjkooa",
"pdjpkfbpeniinkdlmibcdebccnkimnna",
"hmpjibmngagmkafmijncjokocepchnea",
"kljbaedmklfnlgfmmbodnckafhllkjnd",
"lmppkgmbapjgihlpadknmfalefnfnfnd",
"ldghoefcghcinacfneopmnechojlhldf",
"mgjfjcimpkdjgeldkcaoboiojmlcleka",
"aghafppaelpjbjajpgcogcojcbmappoi",
"kgdjeaonamhfooejllllfpeappcgfpod",
"knjgknhkgmedmajpkhooaagjgfgbcndo",
"apoklfecapckgpbbcpaiebemaghmkncf",
"podfjomopoejmlkfnhanlmlagcnlappd",
"idngjfdlfbfgecemidnhbdcogggnjkpg",
"kghabofklgjfnipgkjadlogcjbebkeid",
"fmmfeaoidanfcipomjfolmchjdnhmaio",
"cfmfokegjjljmdcdpnmlfajlddngkoah",
"eoimljninkkepafoijpgbedkkieobfek",
"ojmaccnnagaiokckbcpdldhnifkibcah",
"bhoebgegnjoehioianjnjakeeggajanb",
"edojphplonjclmfckdiolpahpgcanjnh",
"leaglmohfmgdengbciphnodmcgfgdgnf",
"ljdhejdbbogemelgkihbabifpfdfomcc",
"hfokkkgobhlkcagflcbgcokdbnknfngo",
"hilgkhepkfjdkkdigphhcgmghefdledg",
"jipclfaahkhinbelbojjblmbcpkaipko",
"cmckpheolajgbmhlfhgelajhhfgjbhpk",
"jjdhjfgoadphekgihokkigfghndfmffb",
"nelegdbdfopcgkignnifhdoiapldlhpf",
"dnojfjfegklgconkoekfkaajejmdgdkj",
"nnceocbiolncfljcmajijmeakcdlffnh",
"dacliiapfipnlipdmifioaijepgmhdga",
"cpbbiepjnljbnngpepgeaojjeneacpld",
"ocopipabchoopeppmgiigphgbicocoea",
"gfechfioaanebemclajhfgkfaopcaibo",
"hoclolhilhbecpefaignjficiaaclpop",
"ibmdocjlknaopfecmnojomdlbeadpdnb",
"ckdbfeccfocmhdclmmofmheljglmhhne",
"gddkghdkhhlihaabphhnjbhdoiifhcpa",
"{34b0d04c-29cf-473c-bb6c-c2fe94377b99}",
"{7cc10397-c6f4-4a27-a1e7-83b870dd6cab}",
"{99d4bddd-5452-4216-83bc-fcd57857b6fb}",
"{f7d2c8aa-e06e-4117-8b99-52a145eb7d23}",
"{5f246670-f5e2-45ff-b183-be21cbeb065a}",
"{c257a965-0bf8-4934-bf85-9ebf761d1cf8}"
]);
DeviceTvmBrowserExtensions
| where ExtensionId in (extension_ids)
```

Can also be detected from DeviceFileEvents as the extension id is part of the Folder path.

```KQL
let extension_ids = dynamic([
"aikflfpejipbpjdlfabpgclhblkpaafo",
"dbfmnekepjoapopniengjbcpnbljalfg",
"nnnkddnnlpamobajfibfdgfnbcnkgngh",
"ppfdcmempdfjnanjegmjhanplgjicefg",
"fmiefmaepcnjahoajkfckenfngfehhma",
"edojphplonjclmfckdiolpahpgcanjnh",
"bjehnpiidogpaocjjfhnopdjcahigggm",
"kdgjiakonpbfmndaacfhamdoangincgp",
"dihekmadkkcgnffajefocfamnpimlhah",
"eijnkinhnplaekpllmgbbfieecdhcmcp",
"mdlkdelnchilkeedllnnjfigkhhadlff",
"agepkkdokhlaoiaenedmjbfnblfdiboc",
"epepbcdeelckgplpmmmnmjplbeipgllo",
"makeekhnfplggoaiklkphfopajegajci",
"cahdpfhnokmnnjhoaoliabdbcbbokmgc",
"mmpfmolbdhdfoblfggigchncdgmdnjha",
"knejepegjmjmjlhficbikmblnbemdpke",
"cjlabngphhjjdapemkdnpgkpebkpjbbe",
"jeaebbdndojkbnnfcaihgokhnakocbnf",
"bajoeadpdidoahbhphmhejmbdmgnbdci",
"goiffchdhlcehhgdpdbocefkohlhmlom",
"djkddblnfgendjoklmfmocaboelkmdkm",
"codgofkgobbmgglciccjabipdlgefnch",
"cicnbbdlbjaoioilpbdioeeaockgbhfi",
"mchacgmgddefeohkjobefhihbadocneh",
"oelcnhfgpdjeocflhhfecinnpjojeokp",
"fllcifcfhgmmfpogmpedgbjccnjalpjo",
"fmgaogkbodhdhhbgkphhbokciiecllno",
"dkbpkjhegfanacodkmfjeackckmehkfp",
"jooiimddfkjoomennmpjabdbbpdocjng",
"dekjibpkbhgbnmnfibnibnjoccaphfog",
"mnamhmcgcfflfjafflanbhbfffpmkmmm",
"ambcheakfbokmebglefpbbphbccekhhl",
"nmaegedpdmepbkahckadmaolllgmogma",
"doeomodlafdbbnajjllemacdfphbbohl",
"meobjhkdifjealkiaanikkpajiaalcad",
"kfdopiiledmclnopmihkclnfgdiggjna",
"cfgiodgnkinmacjkgjgdejeciohojglp",
"okepehobneenpbhiendcjcanjodhmcbj",
"cdgonefipacceedbkflolomdegncceid",
"bgkdocoihppjkdfaghndpjlfoehjcmka",
"ldmnodpmebcfcdkejkdakphbcjnmejlf",
"pdfladlchakneeclhmpoboohikpbchkj",
"gipnpcencdgljnaecpekokmpgnhgpela",
"idholfkkmfccbondfiabhlmdfeamnnaj",
"bpgaffohfacaamplbbojgbiicfgedmoi",
"jdehnhjckcbfdkgnlbfjokofagpbbdgl",
"dijcdmefkmlhnbkcejcmepheakikgpdg",
"gndlcpbcmhbcaadppjjekgbhfhceeikm",
"lepdjbhbkpfenckechpdfohdmkhogojf",
"hbjeophpjnopmeheabcilmgdhnnjbmbo",
"dlfjoijnhjeagkenhbililbdiooginng",
"kolgdodmgnnhnijmnnidfabnghgakobl",
"edohfgmjmdnibeihfcajfclmhapjkooa",
"pdjpkfbpeniinkdlmibcdebccnkimnna",
"hmpjibmngagmkafmijncjokocepchnea",
"kljbaedmklfnlgfmmbodnckafhllkjnd",
"lmppkgmbapjgihlpadknmfalefnfnfnd",
"ldghoefcghcinacfneopmnechojlhldf",
"mgjfjcimpkdjgeldkcaoboiojmlcleka",
"aghafppaelpjbjajpgcogcojcbmappoi",
"kgdjeaonamhfooejllllfpeappcgfpod",
"knjgknhkgmedmajpkhooaagjgfgbcndo",
"apoklfecapckgpbbcpaiebemaghmkncf",
"podfjomopoejmlkfnhanlmlagcnlappd",
"idngjfdlfbfgecemidnhbdcogggnjkpg",
"kghabofklgjfnipgkjadlogcjbebkeid",
"fmmfeaoidanfcipomjfolmchjdnhmaio",
"cfmfokegjjljmdcdpnmlfajlddngkoah",
"eoimljninkkepafoijpgbedkkieobfek",
"ojmaccnnagaiokckbcpdldhnifkibcah",
"bhoebgegnjoehioianjnjakeeggajanb",
"edojphplonjclmfckdiolpahpgcanjnh",
"leaglmohfmgdengbciphnodmcgfgdgnf",
"ljdhejdbbogemelgkihbabifpfdfomcc",
"hfokkkgobhlkcagflcbgcokdbnknfngo",
"hilgkhepkfjdkkdigphhcgmghefdledg",
"jipclfaahkhinbelbojjblmbcpkaipko",
"cmckpheolajgbmhlfhgelajhhfgjbhpk",
"jjdhjfgoadphekgihokkigfghndfmffb",
"nelegdbdfopcgkignnifhdoiapldlhpf",
"dnojfjfegklgconkoekfkaajejmdgdkj",
"nnceocbiolncfljcmajijmeakcdlffnh",
"dacliiapfipnlipdmifioaijepgmhdga",
"cpbbiepjnljbnngpepgeaojjeneacpld",
"ocopipabchoopeppmgiigphgbicocoea",
"gfechfioaanebemclajhfgkfaopcaibo",
"hoclolhilhbecpefaignjficiaaclpop",
"ibmdocjlknaopfecmnojomdlbeadpdnb",
"ckdbfeccfocmhdclmmofmheljglmhhne",
"gddkghdkhhlihaabphhnjbhdoiifhcpa",
"{34b0d04c-29cf-473c-bb6c-c2fe94377b99}",
"{7cc10397-c6f4-4a27-a1e7-83b870dd6cab}",
"{99d4bddd-5452-4216-83bc-fcd57857b6fb}",
"{f7d2c8aa-e06e-4117-8b99-52a145eb7d23}",
"{5f246670-f5e2-45ff-b183-be21cbeb065a}",
"{c257a965-0bf8-4934-bf85-9ebf761d1cf8}"
]);
DeviceFileEvents
| project Timestamp, ActionType, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, DeviceName, DeviceId
| where FolderPath has_any (extension_ids)
| summarize min(Timestamp), max(Timestamp), ActionTypes = make_set(ActionType), FolderPaths = make_set(FolderPath) by DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessAccountName
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                                 |
| ------------------- | ------------ | ------------------------------------------------------------------------------ |
| Persistence         | T1547        | [Software Extensions: Browser Extensions](https://attack.mitre.org/techniques/T1176/001/)|
| Exfiltration        | T1041        | [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)     |


## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-01-27 | Initial query published           |