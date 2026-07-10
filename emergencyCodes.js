// Bewust NIET in de Postgres-database: dit is een noodcode (alleen als hash, nooit als platte
// tekst) die tijdelijk via de server wordt doorgegeven aan het kind-apparaat en daar lokaal wordt
// opgeslagen. Zo kan een ouder het apparaat ook ontgrendelen zonder internetverbinding, en staat
// de code niet permanent in een database-backup. Bij een herstart van de server is deze lijst leeg
// — dat is bewust: het kind-apparaat blijft de laatst opgehaalde hash gewoon lokaal gebruiken.
const codeHashByChildId = new Map();

module.exports = { codeHashByChildId };
