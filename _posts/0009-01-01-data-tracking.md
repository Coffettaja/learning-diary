---
title: '21: Data Tracking'
layout: posts
---

Mobiiliapplikaatiot ovat todella yleisessä käytössä, ja ne on helppo ladata ja
asentaa esimerkiksi älypuhelimeen. Niillä on kuitenkin myös suuret valtuudet
käyttäjän dataan (mikäli käyttäjä sallii tämän), joten on mahdollista, että ne väärinkäyttävät käyttäjän sensitiivistä
dataa, joko tarkoituksella tai vahingossa. Ne saattavat esimerkiksi vuotaa käyttäjän
olinpaikan mainospalveluille tai muuttaa laitteen spam-botiksi. Paperin tutkimuksen
mukaan 30:stä satunnaisesti valitusta sensitiivistä dataa käyttävästä
Android-applikaatiosta kaksi kolmasosaa käytti tätä dataa epäilyttävällä tavalla.

Naiivi ratkaisu sensitiivisen datan vuotamista vastaan on, että laitteelle ei
asennettaisi appeja, joilla on valtuudet sekä dataan että verkkoon. Tämä kuitenkin estäisi esimerkiksi sähköposti-appien käytön. Lisäksi
ratkaisu ei estäisi tapauksia, joissa useampi appi eri valtuuksilla toimii yhteystyössä. 
Toimivampi ratkaisu on sensitiivisen datan jäljittäminen ja sen käytön estäminen 
verkko&shy;kutsujen parametreina. Android-äly&shy;puhelimien tapauksessa tähän voidaan käyttää
TaintDroid-systeemiä.

TaintDroid perustuu sensitiiviseen dataan liittyvien tekijöiden merkkaamiseen 
ns. *taintilla*, jota levitetään applikaation muihin osiin datan kulun mukaisesti.  
*Taint* on 32 bitin bittivektori, mikä mahdollistaa tehokkaiden
bitti-operaatioiden kuten yhdisteen hyödyntämisen *taintin* levittämisessä. Alkuun
*taint* asetetaan datan alkuperässä, sitten sitä levitetään sääntöjen perusteella
ja lopulta kun merkattua dataa ollaan lähettämässä esimerkiksi verkkoon, *taint*
tarkastetaan ja sen pohjalta tehdään päätös seuraavasta toiminnosta, joka voi olla
esimerkiksi käyttäjälle ilmoittaminen tai datan nollaaminen.

*Taint* asetetaan systeemin käynnistyksessä, jolloin TaintDroid tarkistaa kaikki 
mahdolliset sensitiivisen datan lähteet ja asettaa merkin tarvittaessa. Sitten
*taint* leviää neljällä eri tasolla: muuttujien, metodien, viestien ja tiedostojen
tasolla. Tämä tarkoittaa, että esimerkiksi kun merkattua muuttujaa käytetään toisen
muuttujan arvon asettamiseen, niin myös tämä toinen muuttuja merkataan.
*Taintin* leviämisen säännöt riippuvat tarkemmin merkin omaavasta osasta. Esimerkiksi
taulukkojen tapauksessa *taint* yliarvioidaan varmuuden vuoksi. TaintDroid ei kuitenkaan
osaa käsitellä oikein tilanteita, joissa jonkin muuttujan arvo riippuu epäsuorasti
merkatusta muuttujasta, esimerkiksi kun merkattu muuttuja on if-lauseen ehtona ja
toinen muuttuja asetetaan if-lauseen sisällä.

TaintDroidin käyttö aiheuttaa suhteellisen pienet kustannukset suoritus&shy;kyvylle. *Taint*-
merkkien tallentaminen aiheuttaa n. 3-5% kustannuksen muistille. Toisaalta *taintin*
levittäminen voi aiheuttaa lähes 30% kustannuksia CPU:lle, mikä puolestaan voi
huomattavasti alentaa laitteen akkukestoa.

*Taintin* jäljittämistä on pyritty hyödyntämään myös Androidin ulkopuolisissa
systeemeissä. Kuitenkin x86-tasolla jäljittäminen on raskasta ja lisäksi
on vaara *taintin* räjähdysmäiselle leviämiselle, mikäli esimerkiksi *stack
pointteri* merkataan saastuneeksi. Vanhojen C ja C++ -ohjelmien tapauksessa
*tainttia* voidaan jäljittää TightLip-systeemillä. TightLip hyödyntää ns.
kaksoisolento&shy;prosesseja, mikä mahdollistaa datan vuotamisen jäljittämisen
*taintin* avulla myös silloin, kun alkuperäistä systeemiä ei voida muokata
lainkaan. Kaksoisolento&shy;prosessi on hyvin samanlainen kuin alkuperäinen, mutta
se ei koske sensitiiviseen dataan. Mikäli nämä kaksi prosessia siitä huolimatta kutsuvat
samoja systeemikutsuja samoilla argumenteillä, voidaan päätellä, että alkuperäinen
prosessi ei tarvitse toimiakseen sensitiivistä dataa.

### Ajatuksia materiaalista

Sensitiivisen datan jäljittäminen mobiili&shy;laitteilla on varsin mielenkiintoinen aihe.
Itse olen aina ollut vastentahtoinen sallimaan erinäisten appien käyttää laitteeni
dataa, varsinkin kun monesti ei ole selkeää, mihin appi tarvitsee tätä. Olikin
yllättävää lukea, että jopa yli puolet satunnaisesti valituista apeista käytti
dataa jotenkin väärin. Ei taida vielä nykyäänkään olla Android-laitteissa oletuksena
käytössä jotain sensitiivisen datan kulkua tarkkailevaa systeemiä. En ainakaan
ole koskaan saanut esimerkiksi huomautusta puhelimeltani, että dataa käytettäisiin
väärin, vaikka väärin&shy;käyttö vaikuttaisi olevan varsin yleistä. 
