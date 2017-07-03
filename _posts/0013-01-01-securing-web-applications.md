---
title: '9: Securing Web Applications'
layout: posts
---

Tällä luennolla jatkettiin aikaisemman luennon teemaa esittelemällä lisää heikkouksia web sovelluksissa. Yksi esitelty hyökkäys oli ns. ‘***shell shock***’ bugin hyödyntäminen, jolloin hyökkääjä pystyy http-pyyntöjen otsikoiden avulla ajamaan haluamaansa koodia cgi-palvelimella. Tämä johtuu siitä, että cgi-palvelin muuntaa http-otsikon ja sen arvon bashin muuttujaksi. Hyökkääjä voi helposti sekoittaa bashin *parserin*, ja siten ajaa omaa koodia.
 
Toinen lyhyesti esitelty hyökkäys oli **SQL-injektio**. Injektiot johtuvat siitä, että käyttäjältä saatua (ja täten epäluotettavaa) dataa käytetään sellaisenaan SQL-kyselyissä. Kolmas hyökkäys oli ns. GIFAR-hyökkäys, jonka perustana oli .jar-tiedostojen piilottaminen .gif-tiedostoihin, jolloin oli mahdollista ajaa Java-skriptejä. 

Vielä yksi hyökkäysmahdollisuus liittyi uhrin vierailemien nettisivujen urkkimiseen. Esitelty hyökkäys perustui linkkien tilan seuraamiseen JavaScriptin avulla, jolloin hyökkääjä pystyi päättelemään linkkien avulla, oliko uhri vieraillut linkkejä vastaavilla sivuilla. Hyökkääjän sivulla on todella paljon linkkejä, mutta ne ovat piilotettu, jolloin uhri ei edes havaitse mitään merkillistä. Nykyään selaimet eivät enää paljasta JavaSciptille linkkien tilaa. Vastaava hyökkäys on kuitenkin mahdollista suorittaa tarkkailemalla, kuinka nopeasti vaaditut objektit saapuvat: mikäli ne saapuvat nopeasti, voidaan päätellä, että ne olivat välimuistissa. Näiden lisäksi oli vielä kaksi muuta hyökkäyskeinoa siltä varalta, että välimuistiin varastoiminen estettäisiin kokonaan.
 
‘***Cross-site scripting***’ -hyökkäyksiä vastaan esiteltiin joitakin puolustusmekanismeja. Useimmissa selaimissa on valmiina filttereitä XSS-hyökkäyksien varalta, mutta ne on valitettavasti helppo ohittaa. Vastaavasti esimerkiksi Django-frameworkissa pyritään hyödyntämään sanitaatiota, mutta tässäkin tapauksessa ohittaminen on mahdollista. On mahdollista myös hyödyntää oikeuksien erottelua sijoittamalla kaikki epäluotettava sisältö toiselle *domainille*. Tällöin hyökkäyksen sattuessa vahinko olisi rajoittunut vain tälle ulkoiselle domainille. Voidaan myös kuvata ns. ‘*content security policy*’, jolloin palvelin kertoo selaimelle, että mitä sisältöä voidaan ladata ja mistä tämän sisällön pitää tulla. On myös mahdollista asettaa ns. *httponly*-evästeitä, jolloin asiakkaan puolen JavaScript ei voisi päästä käsiksi tähän evästeeseen.
 
Evästeet voivat usein olla turvallisuusriski, sillä hyökkääjä voi esimerkiksi varastaa evästeen ja näin hyödyntää siinä ollutta sessionin dataa. Tämän vuoksi on ehdotettu ns. tilattomien evästeiden käyttöä, jolloin jokainen asiakkaalta tullut pyyntö pitäisi autentikoida. Tämä voidaan tehdä jakamalla asiakkaan ja palvelimen kesken salaisen avaimen, jonka avulla palvelin voi tunnistaa asiakkaan pyynnöt. Tätä käytetään lähinnä palvelimien väliseen kommunikointiin.
 
Evästeiden käyttö voitaisiin teoriassa välttää myös hyödyntämällä DOM-varastoa tallentamaan evästeiden dataa. Yksittäinen varasto on kuitenkin vahvasti sidoksissa yksittäiseen alkuperään (*origin*). Toinen keino on hyödyntää asiakkaan puolella sijaitsevia sertifikaatteja, joihin JavaScript ei voi päästä käsiksi. Näiden haittapuolena on kuitenkin niiden epäkäytännöllisyys, sillä jokaista sivua varten joutuisi asentamaan omat sertifikaatit. Lisäksi on varsin hankalaa ottaa sertifikaattia pois käyttäjältä tarpeen vaatiessa.
 
 
### Ajatuksia materiaalista
 
Tällä luennolla tuli varmaan 15 uutta heikkoutta / hyökkäysmahdollisuutta jo aikaisemmin esiteltyjen päälle. Aika vaikea pitää kirjaa kaikista, varsinkin jos haluaa vielä tietää, mistä ne johtuvat ja miten niiltä kuuluisi suojautua. Lisäksi monille näistä ei edes esitelty käytännöllistä puolustautumiskeinoa ollenkaan. Kaiketi ne tärkeimmät takeawayt luennolta olisi, että käyttäjältä tulevaa epäluotettavaa dataa pitää varoa ja että täydellinen puolustautuminen on käytännössä mahdotonta.
 
Olisi kiva, jos luennolla esitettäisiin konkreettisemmin joitakin oleellisia asioita, joihin hyökkäykset ja puolustukset littyvät. Itse en ainakaan ole luennon perusteella ollenkaan varma, miten esimerkiksi tilattomien evästeiden kohdalla esitellyt ‘*Message Authentication Code*’-koodit toimivat, joten aika vaikea sisäistää, miksei niitä käytetä yleisemmin tai miten sellainen pitäisi toteuttaa itse.
