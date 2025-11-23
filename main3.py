import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

WIKIDATA_SPARQL_ENDPOINT = "https://query.wikidata.org/sparql"

HEADERS = {
    "User-Agent": "WikidataIdentifiersChecker/1.0 (example@example.com)"
}


def url_works(url: str) -> bool:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
        return 200 <= resp.status_code < 300
    except requests.RequestException:
        return False


def try_direct_rdf(url: str):
    lower = url.lower()
    if lower.endswith(".rdf"):
        return url if url_works(url) else None

    rdf_url = url + ".rdf"
    if url_works(rdf_url):
        return rdf_url

    return None


def find_rdf_links_in_html(url: str):
    rdf_links = set()

    try:
        resp = requests.get(url, headers=HEADERS, timeout=30, allow_redirects=True)
        if not (200 <= resp.status_code < 300):
            return []

        soup = BeautifulSoup(resp.text, "html.parser")

        # <a href="...">
        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            if full.lower().endswith(".rdf"):
                rdf_links.add(full)

        # <link rel="...">
        for link in soup.find_all("link", href=True):
            full = urljoin(url, link["href"])
            if full.lower().endswith(".rdf"):
                rdf_links.add(full)

    except requests.RequestException:
        return []

    return list(rdf_links)


def get_identifier_urls(qid: str):
    """
    Zwraca listę (propertyLabel, identifier, url) dla wszystkich ExternalId.
    """
    query = f"""
    SELECT ?property ?propertyLabel ?id ?url WHERE {{
      wd:{qid} ?propStatement ?statement .
      ?property wikibase:claim ?propStatement ;
                wikibase:propertyType wikibase:ExternalId .
      ?statement ?ps ?id .
      ?property wikibase:statementProperty ?ps .

      OPTIONAL {{ ?property wdt:P1630 ?formatterUrl . }}

      BIND(
        IF(
          BOUND(?formatterUrl),
          IRI(REPLACE(STR(?formatterUrl), "\\\\$1", STR(?id))),
          IRI(STR(?id))
        ) AS ?url
      )

      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }}
    """

    resp = requests.get(
        WIKIDATA_SPARQL_ENDPOINT,
        params={"query": query, "format": "json"},
        headers=HEADERS,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    results = []
    for b in data["results"]["bindings"]:
        label = b["propertyLabel"]["value"]
        identifier = b["id"]["value"]
        url = b["url"]["value"]
        results.append((label, identifier, url))
    return results


def check_identifier_url(url: str):
    """
    Sprawdza: działa/nie działa, finalny URL, oraz wszystkie źródła .rdf.
    Zwraca tuple:
        (is_alive, final_url, rdf_candidates)
    """
    try:
        resp = requests.get(url, headers=HEADERS, timeout=20, allow_redirects=True)
    except requests.RequestException:
        return False, url, []

    if not (200 <= resp.status_code < 300):
        return False, resp.url, []

    final_url = resp.url

    rdf_list = []

    # 1) prosty przypadek: URL + ".rdf"
    rdf_direct = try_direct_rdf(final_url)
    if rdf_direct:
        rdf_list.append(rdf_direct)

    # 2) przypadek: skanowanie HTML pod kątem .rdf
    rdf_html = find_rdf_links_in_html(final_url)
    rdf_list.extend(rdf_html)

    return True, final_url, list(set(rdf_list))


def main():
    qid = "Q127345"
    identifiers = get_identifier_urls(qid)

    print(f"Znaleziono {len(identifiers)} identyfikatorów dla {qid}.\n")

    for prop_label, identifier, url in identifiers:
        alive, final_url, rdf_urls = check_identifier_url(url)

        print("======================================")
        print(f"Właściwość:  {prop_label}")
        print(f"ID:          {identifier}")
        print(f"URL oryg:    {url}")
        print(f"URL finalny: {final_url}")

        if not alive:
            print("STATUS: ERROR Strona nie działa\n")
            continue

        if rdf_urls:
            print("Znalezione RDF:")
            for r in rdf_urls:
                print("   ✔", r)
        else:
            print("RDF: brak")

        print()


if __name__ == "__main__":
    main()
