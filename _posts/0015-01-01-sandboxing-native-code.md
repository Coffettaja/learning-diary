---
title: '7: Sandboxing Native Code'
layout: posts
---

NaCl (*Native Client*) on Googlen kehittämä sandboxaus-teknologia, joka mahdollistaa mm. epäluotettavalta taholta saadun C ja C++ -koodin ajamisen selaimessa turvallisesti. Tämän ansiosta voidaan saavuttaa korkeampi suorituskyky sekä välttää JavaScriptin käyttö tarvittaessa. Siitä huolimatta nettisivu tarvitsee JavaScriptia vähintäänkin vuorovaikuttamaan NaCl:n kanssa.
 
NaCl:ssa sandboxausta lähestytään niin sanotun ohjelmistovirheiden eristämisen (engl. *software fault isolation*) kautta. Ideana on etukäteen tarkistaa annetun koodin käskyt ja varmistaa, että ne ovat turvallisia suorittaa. Jotkin operaatiot kuten matemaattiset operaatiot ja muut turvalliseksi katsotut operaatiot automaattisesti sallitaan. Muiden operaatioiden tapauksessa ne joko estetään tai instrumentoidaan niiden tarpeellisuuden perusteella. Tässä instrumentoinnilla tarkoitetaan, että käskyn eteen lisätään hyvän lopputuloksen takaavia käskyjä. 
 
Niin NaCl:ssä kuin yleensä kaikissa muissakin ohjelmistovirheiden eristämistapauksissa käytössä on myös ns. luotettava ajonaikainen palvelu. NaCl:n tapauksessa tämä on Googlen tekemä, joten siihen voidaan yleensä luottaa. Tämä palvelu mahdollistaa useita sellaisia toimenpiteitä, joita muualta tuleva koodi ei saa suorittaa, esimerkiksi verkkoon käsiksi pääsyn ja näppäimistön kuuntelemisen. 
 
NaCl:n turvallisuuden takaamiseksi käytössä on useita sääntöjä. Ensinnäkin kiellettyjen käskyjen ajaminen on estetty. Lisäksi kaiken koodin ja datan täytyy olla tuodun moduulin rajojen sisällä. Käytetyssä arkkitehtuurissa käskyjen pituudet voivat vaihdella, joten niiden pituus tallennetaan niiden alkuun. Kuitenkin hypyt koodissa vaikeuttavat käskyjen turvallisuuden takaamista, sillä on mahdollista hypätä jonkin käskyn keskelle. Luotettava *disassemblaus* voidaan varmistaa tarkistamalla, minne kykin hyppy johtaa ja varmistamalla, että hypyn kohteena oleva käsky on tullut jo aikaisemmin vastaan. 

Epäsuorien hyppyjen varalle käskyille myös varataan 32 tavun alue, joiden rajaa ne eivät saa ylittää. Lisäksi varmistetaan, että hypyt voivat johtaa vain 32:lla jaollisiin alueisiin, eli näiden käskyjen alueiden rajalle, jolloin aina ollaan jonkin käskyn alussa. Nyt kaikki käskyt ovat saavutettavissa *dissassembloimalla* alusta asti.
 
 Jotta epäluotettava moduuli voisi hyödyntää sandboxin ulkopuolella olevaa luotettavaa palvelua, käytössä on ns. **trampoliinit** palveluun pääsyn varalle ja **ponnahduslaudat** sieltä takaisin pääsyä varten. Trampoliinilla tarkoitetaan moduulin prosessille varatussa tilassa olevaa valmista käskyä, joka hyppää luotettavaan palveluun. Näin moduulista käsin voidaan suorittaa esimerkiksi systeemikutsu, sillä ulkopuolinen palvelu varmistaa sen turvallisuuden. Ponnahduslaudan avulla voidaan palata takaisin itse moduulin ajoon.
 
 
### Ajatuksia materiaalista
 
Tällä luennolla jo melkein päästiin nykypäivänä käytettävään teknologiaan. NaCl oli varmasti muutama vuosi sitten luennon kuvauksen aikaan lupaava tulevaisuuden teknologia, vaikka ei se ilmeisesti silloinkaan ollut käytössä muualla kuin Googlella avoimesta lähdekoodista huolimatta. Kuitenkin juuri nyt kesän alusta taisi varmistua, että *Portable Native Clientin* tuki lakkautetaan ensi vuoden alusta WebAssemblyn suosion vuoksi. Hassua / masentavaa ajatella, että näinkin pitkään työstetty ja pitkälle mietitty projekti jää hyödyntämättä vain, koska toinen vastaavanlainen projekti syystä tai toisesta nousi suurempaan suosioon.
 
NaCl:ssä itseäni ainakin jäi epäilyttämään siinä käytetty Googlen tekemä ‘*trusted service runtime*’. Nimensä mukaanhan sen pitäisi olla luotettava ja varmasti todella taitavia tyyppejä on ollut sitä kehittämässä. Kuitenkin se on niin iso osa systeemin turvallisuutta, että pienikin bugi voi vaarantaa koko sandboxin toiminnan, ja jo luennollakin mainittiin muutamia bugeja, jota tästä oli jo silloin löydetty. Muuten NaCl vaikutti varsin järkevältä idealta, ja sen avulla olisi mahdollista luoda vaikka selaimessa toimivia pelejä hyvällä suorituskyvyllä. Tietysti lisäksi JavaScriptin osittainen kiertäminen voi olla myös plussaa... Nämä mahdollisuudet ovat ainakin lähitulevaisuudessa enemmän wasmin ja ehkä myös asm.js:n varassa.