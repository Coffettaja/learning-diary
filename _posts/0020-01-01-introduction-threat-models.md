---
title: '1: Introduction, Threat Models'
layout: posts
---

Osa ohjelmisto&shy;turvallisuuden määritelmää voisi olla, että jonkin systeemin tavoite voidaan saavuttaa huolimatta jonkin vastapuolen haitallisesta toiminnasta. Näin turvalliset järjestelmät ovat vastustus&shy;kykyisiä ns. “pahoille henkilöille”. Ohjelmisto&shy;turvallisuus koostuu kolmesta osasta: **toiminta&shy;periaatteesta** (engl. *policy*), **uhkamallista** (engl. *threat model*) ja **mekanismeista**. 

Toiminta&shy;periaatteella tarkoitetaan jotakin turvallisuuteen liittyvää tavoitetta, esimerkiksi tietojen salassa&shy;pitoon sekä systeemin ehjyyteen ja saavutet&shy;tavuuteen liittyen. Lähes kaikissa systeemeissä toiminta&shy;periaatteessa määritellään, ketkä henkilöt voivat käyttää systeemiä ja millä oikeuksilla.  Uhkamallilla tarkoitetaan vastapuoleen liittyviä oletuksia, joiden pohjalta systeemin turvallisuutta voidaan rakentaa. Yleensä voidaan esimerkiksi olettaa, että vastapuolella ei ole systeemin salasanaa tai keinoa päästä fyysisesti käsiksi systeemiin. Kuitenkin pitää huomioida, että vastapuoli saattaa pyrkiä esimerkiksi arvaamaan tai varastamaan salasanan. Mekanismeilla viitataan ohjelmistoihin ja laitteistoihin, joilla pyritään noudattamaan systeemin toiminta&shy;periaatetta. Näitä ovat esimerkiksi käyttäjätilit, salasanat ja tietojen salaus. Tavoitteena on, että uhkamallia noudattava vastapuoli ei voisi millään tavalla uhata systeemin toimintaa.
	
Ohjelmisto&shy;turvallisuuden murtumia voi tapahtua millä tahansa sen kolmesta osa-alueesta. Esimerkki toiminta&shy;periaatteeseen liittyvästä epäonnistumisesta voisi olla se, että salasanan syöttämiselle ei ole asetettu rajoitetta tai viivettä yritysten välille. Näin vastapuoli voi vaikkapa skriptin avulla nopeasti arvata kaikki yleisimmät salasanat, ja luultavasti lopulta pääsee systeemiin sisälle. Onkin tarpeen miettiä toiminta&shy;periaate tarkasti varsinkin silloin, kun useat systeemit ovat vuoro&shy;vaikutuksessa keskenään.

Iso uhkakuviin liittyvä ongelma on systeemiin liittyvistä ihmisistä johtuva murtuma turvallisuudessa. Käyttäjät saattavat esimerkiksi vahingossa antaa salasanansa vastapuolelle esimerkiksi *phishing* -hyökkäyksen vuoksi. Onkin suositeltavaa, että käyttäjään ei koskaan täydellisesti luotettaisi. 

Mekanismeihin liittyvät murtumat johtuvat useimmiten bugista tai jonkin asian huomiotta jättämisestä. Yksi esimerkki oleellisen asian huomiotta jättämisestä on jonkin web sovelluksen url-osoitteen *‘id’ string query* -parametrin muuttaminen, ja näin voisi päästä käsiksi toiseen käyttäjä&shy;tiliin. Toinen hyvin oleellinen mekanismeihin liittyvä ongelma on ns. puskuri&shy;ylivuoto (engl. *buffer overflow*), joka voi tulla vastaan varsinkin huonosti toteutetuissa C- tai C++-ohjelmissa. Puskuri&shy;ylivuodolla tarkoitetaan, että syötteellä voidaan kirjoittaa sille pinossa varatun tilan ulkopuolelle. Näin hakkeri voisi esimerkiksi saada ohjelman kutsumaan haitallista skriptiä. Tämä voidaan osittain estää kieltämällä skriptien ajamisen pinon kautta.

Yleinen turvallisuus&shy;ohje mekanismeihin liittyen on se, että turvallisuuden kannalta oleellisten mekanismien määrä pitäisi pitää mahdollisimman pienenä. Näin kriittisten virheiden mahdollisuus pienenee. 

 
### Ajatukset materiaalista
 
Ensimmäisellä luennolla päästään aiheeseen mielenkiintoisesti käsiksi monien hyvien esimerkkien kautta. Esimerkkien ansiosta ohjelmisto&shy;turvallisuuden tärkeys tuli hyvin ilmi sekä lisäksi ne selkeyttivät huomattavasti pelkkiä määritelmiä paremmin, mitä turvallisuuden eri osa-alueilla oikein tarkoitetaan. Luennolla tuli hyvin ilmi, kuinka monella eri tavalla systeemin turvallisuus voi särkyä.

Useiden eri uhkakuvien vuoksi itselleni syntyi sellainen tunnetila, että miten voi mitenkään mahdollisesti tehdä tarpeeksi turvallisen systeemin. Omalla tavallaan pelottavaa lähteä luomaan esimerkiksi nettikauppaa tai muuta sovellusta, joka käsittelee käyttäjien pankkitietoja. Mikäli sovelluksen turvallisuus pettää, asiakkaalle voi syntyä suurta vahinkoa. Tätä varten on tietysti luotu yleisesti käytettyjä työkaluja ja API:tä, mutta myös ne saattavat pettää. Suurempi riski on kuitenkin oma huolimattomuus&shy;virhe, niitä kuitenkin ainakin omalla kohdallani sattuu ohjelmoidessa varsin usein. Kääntäjä ei nimittäin valita turvallisuuteen liittyvistä virheistä samalla tavalla kuin se valittaisi puuttuvasta puolipisteestä. Tämän kurssin kautta kuitenkin ohjelmisto&shy;turvallisuuteen asiohin littyen ymmärrys luultavasti kasvaa ja sitä mukaan myöskin itseluottamus sovelluksia ohjelmoitaessa ja suunniteltaessa.

Luennon loppuosassa käytiin yksityiskohtaisesti yksinkertaista C-ohjelmaa ja siihen liittyvää puskuriylivuotoa läpi. Aihe oli mielenkiintoinen, mutta en valitettavasti muista kovinkaan paljoa pinon tai C-kielen toiminnasta, joten sitä oli varsin vaikea seurata. Eiköhän nämäkin asiat kuitenkin tule kurssin kuluessa taas paremmin mieleen.
