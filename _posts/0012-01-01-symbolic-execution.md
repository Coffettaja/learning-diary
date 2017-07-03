---
title: '10: Symbolic Execution'
layout: posts
---

Symboolisella ajolla viitataan ohjelman mahdollisten polkujen läpikäymiseen symboolisesti konkreettisten arvojen sijasta. Tämä tarkoittaa, että ohjelmakoodia voidaan “ajaa” kiinnittäen huomiota eri muuttujien aiheuttamaan symbooliseen tilaan ja muihin rajoitteisiin. Ohjelman ajon eri poluista ja mahdollisista tiloista muodostuu puu, joka kertoo, millä muuttujan arvoilla jokin ehto voidaan saavuttaa. Tätä voidaan hyödyntää erityisesti testauksessa löytämään esimerkiksi bugeja tai koodialueita, joihin ei ole mahdollista päätyä. Bugejen löytäminen ja korjaaminen nostaa myös systeemin turvallisuutta. Lisäksi symboolisen ajon apuna käytettävät ratkaisijat voivat estää haitallisen ohjelmakoodin ajamisen.
 
Tärkeä osa symboolista ajoa on ohjelmakoodin kuvaaminen loogisina operaatioina. Nämä operaatiot voidaan yrittää ratkaista SAT-ratkaisijoiden avulla. **SAT-ratkaisija** kertoo, onko ratkaisu mahdollinen ja jos on, niin millä arvoilla. Mikäli se huomaa, että ratkaisu ei ole joillakin arvoilla mahdollinen, niin silloisten muuttujien pohjalta luodaan uusia rajoitteita, joiden pohjalta voidaan pyrkiä löytämään toinen ratkaisu. NP-täydellisyyden vuoksi ratkaisija saattaa myös päätyä tilanteeseen, jossa se ei löydä mitään vastausta. Tämän esiintymistä kuitenkin vähentää se, että ohjelmakoodilla on usein tietty looginen rakenne johtuen siitä, että sen on kirjoittanut ohjelmoija, jolla on ollut joku näkemys ohjelman toiminnasta. 
 
Kun SAT-ratkaisijaa laajennetaan erilaisilla teorioilla, saadaan niin kutsuttu SMT (*Satisfiability Modulo Theory*) -ratkaisija. Teoriat voivat koskea esimerkiksi numeroita tai taulukoita, ja niiden avulla voidaan esittää useita erilaisia väitteitä ohjelman koodista.
 	
Symbolisen ajon avulla tehtyä testausta voidaan suorittaa myös automaattisesti huomattavan korkealla kattavuudella. Esimerkiksi KLEE-työkalua käyttäen voidaan tehdä tämä C-koodille. Sen avulla on pystytty saavuttamaan keskiarvoisesti jopa yli 90% kattavuus testattaessa GNU CoreUtilsia, löytäen useita bugeja.
	
### Ajatuksia materiaalista
 
Symboolinen ajo aiheena vaikuttaa mielenkiintoiselta ja käytännössä hyödylliseltä. Luennoilla käytyjen yksinkertaisten esimerkkien jälkeen idea tuntui selkeältä ja loogiselta. Itse luennoitsijan ajatuksen kulussa oli kuitenkin todella vaikea välillä pysyä mukana, joten MIT luennon pohjalta minulle jäi lopulta aika heikko kuva koko hommasta, erityisesti liittyen SMT:hen ja siihen liittyviin teorioihin (taulukkoteoriat yms.) sekä symboolisen ajon yhteydestä ohjelmistoturvallisuuteen. Onneksi kuitenkin Jyväskylän päässä aiheesta pidetyn luennon materiaali jonkin verran selvensi käsitystäni tästä. Jonkin verran yritin googletella aiheesta, mutta aika vaikea oli löytää selkoenglannilla kirjoitettua materiaalia. 
Tämä merkintä valitettavasti jäi hieman liian lyhyeksi, sillä koko luento keskittyi hyvin pitkälti vain yhteen aiheeseen ja siihen liittyvä artikkelikin käsitteli tätä samaa aihetta yksityiskohtaisemmin vähän eri sovelluskohteessa.
