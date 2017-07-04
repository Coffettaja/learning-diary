---
title: '2: Control Hijacking Attacks'
layout: posts
---

Puskuriylivuodot ovat mahdollisia, koska systeemien ohjelmistot, esimerkiksi kääntäjät, serverit ja tietokannat,  ovat usein tehty C-kielellä. Tämä johtuu siitä, että C:n avulla on mahdollista päästä hyvin lähelle itse laitteistoa ja sitä kautta ohjelmoija voi vaikuttaa ohjelmiston toimintaan tarkemmin. Toinen syy on se, että monet systeemit ovat vanhoja ja sisältävät paljon myöskin vanhaa koodia, jota ei yleensä haluta lähteä muokkaamaan. C-kielessä on kuitenkin useita ongelmia. Se mm. altistaa muisti&shy;osoitteet ja näiden rajojen tarkistaminen on yleensä mahdotonta tai vähintäänkin hankalaa. 
 
Toinen ylivuotoja mahdollistava tekijä on x86-arkkitehtuurin vakiintuneisuus. Tämän vuoksi hyökkääjä voi helposti päätellä, miten pino toimii ja hyödyntää tätä tietoa. 
 
Perusajatus puskuriylivuodoissa on jonkin funktion paluuosoitteen muuttaminen pinossa kirjoittamalla jonkin puskurialueen yli. Näin hyökkääjä voi ajaa haitallista koodia kaapatun ohjelman oikeuksilla, millä voi olla todella tuhoisia seurauksia esimerkiksi silloin, jos kaapattu ohjelma on *admin*- tai *superuser*-prosessi. Tämän avulla on mahdollista esimerkiksi ohittaa palomuuri, sillä se luottaa sen sisäpuolella oleviin ohjelmiin. 
 
Puskuriylivuodon ongelmien korjaamiseksi on useita eri lähestymis&shy;tapoja. Ilmeisin keino on bugien välttäminen C-koodissa. Tämä ei tietenkään juuri koskaan ole kokonaan mahdollista, mutta ohjelmoijan pitäisi pyrkiä välttämään ainakin ns. “huonoja tapoja” (engl. *bad practices*), kuten turvattomiksi todettuja funktioita tai tuntemattomia kirjastoja. 

Yksi keino bugien aiheuttamien ongelmien välttämiseksi on hyödyntää työkaluja, jotka pyrkivät tunnistamaan bugeja. **Staattisella analyysillä** voidaan havaita bugeja koodissa, esimerkiksi alustamattomia muuttujia. Voidaan myös hyödyntää ns. *fuzzausta* antamalla funktioille satunnaisia syötteitä ja varmistamalla, että mahdollisimman moni ohjelman haara tulee testattua. Myös staattista analyysia voidaan hyödyntää tämän yhteydessä, esimerkiksi huomioimalla ehtolauseen kaikki haarat. Näillä työkaluilla ei voida kuitenkaan havaita kaikkia ongelmia, ja aihe onkin edelleen jatkuvan tutkimuksen kohteena.
 
Tietysti voidaan myös käyttää muistin kannalta turvallisia ohjelmointi&shy;kieliä, kuten Pythonia tai Javaa. Tämä ei kuitenkaan ole mahdollista esimerkiksi vanhan perintö&shy;koodin kanssa, tai mikäli on tarvetta päästä lähelle laitteistoa, esimerkiksi ajureiden kanssa tai suorituskykyä maksimoitaessa. 
 
On myös mahdollista hyödyntää erityistä arvoa, joka sijoitetaan osoitteisiin juuri ennen paluukäskyn osoitetta (engl. *stack canary*). Ennen paluukäskyn suorittamista tarkistetaan, onko tämä arvo muuttunut. Mikäli arvo on muuttunut, voidaan olettaa, että puskuri&shy;ylivuoto on tapahtunut, ja paluukäskyä ei suoriteta. Mahdollisia arvoja tälle erityisarvolle ovat mm. erilaiset *null*-arvot, koska puskuri&shy;ylivuoto saattaa pysähtyä niihin. Toinen vaihtoehto on käyttää satunnaisia arvoja. Tämä kuitenkaan ei toimi, mikäli hyökkääjä onnistuu arvaamaan arvon. Vaihtoehtoisesti hyökkääjä saattaa muokata vaikkapa tärkeitä pointtereita, ennen kuin tähän erityisarvoon päästään.
 
Ylivuotojen estämiseksi voidaan myös varmistaa, että ennen kuin jotakin tiettyä pointteria käytetään niin se on sallittujen rajojen sisällä (engl. *bounds checking*). Monet näistä keinoista ovat muistin kannalta kalliita, joten niitä voidaan käyttää vain debuggauksen yhteydessä. Yksi parempia keinoja on kuitenkin ns. *baggy bounds checking*, sillä se on suhteellisen kevyt sekä myös yhteensopiva vanhempien sovellusten kanssa. Ideana rajojen tarkistuksessa on ylläpitää datarakennetta, joka sisältää jokaisen varatun objektin ja niiden rajat. Tätä datarakennetta voidaan sitten hyödyntää varmistamaan, että pointerit pysyvät rajojen sisällä. Baggy bounds checkauksessa varatut muistialueet pidetään rajattuina, joten se on tehokkaampi.

 
### Ajatuksia materiaalista
 
Luennon alkuun tuli aika paljon kertausta ensimmäisen luennon asioista liittyen puskuri&shy;ylivuotoihin. Tähän liittyen luennoitsija usein mainitsi, että ongelmat johtuvat hyvin pitkälti C-kielen toimintatavasta ja vanhoista järjestelmistä, jotka edelleen käyttävät C-kielellä kirjoitettuja ohjelmistoja. Itse en juurikaan C:stä tai C++:sta pidä, ja toivottavasti pystyn välttymään näiden käyttämiseltä työelämässä… Toisaalta ongelmia on muissakin kielissä. Esimerkkinä itselleni on jäänyt mieleen ‘A Software Engineer Learns HTML5, JavaScript and jQuery’ -kirjasta otettu kommentti:  "JavaScript contains a number of features that can only truly be regarded as bugs." Tälle annettiin syynä, että uusimmatkin JavaScriptin versiot tehdään aina yhteensopiviksi vanhojen versioiden kanssa, joten ongelmia ei koskaan korjata. 
 
Kertausosuuden jälkeen luennolla siirryttiinkin tarkastelemaan asioita huomattavasti yksityis&shy;kohtasemmin pinon ja Assemblerin kautta. Ensimmäisen luennon aikana en vielä jaksanut näitä asioita juurikaan kertailla, mutta tämän toisen luennon kohdalla se tuli jo melkein pakolliseksi. Keskeytinkin luennon seuraamisen noin 40 minuutiksi ja kertasin tarpeelliset asiat Googlen ja YouTuben avulla. Siitä huolimatta varsinkin luennon loppua kohden en rehellisesti sanottuna ymmärtänyt joitakin asioita kunnolla. 
 
Luennon lopuksi käsiteltiin epäselviä kohtia ‘*baggy bounds*’ -artikkelista, mikä hyvin avasi vaikeasti ymmärrettävää artikkelia. Artikkeliin liittyen koitin googletella *baggy bounds* -lähestymistapaa, mutta nopealla haulla kaikki tulokset olivat vain tieteellisiä tekstejä. Liekkö tällä sitten toinen nimi käytännön tasolla?
 
Lopuksi pitää vielä mainita, että usein luennon aikana joitakin opiskelijoiden esittämiä kysymyksiä oli videolta todella hankala kuulla, joten myös tämä hankaloitti luennon seuraamista. Lisäksi luennoitsijan käsiala oli varsin epäselvää, mikä teki taululle kirjoitettujen koodipätkien ymmärtämisen hankalaksi. 