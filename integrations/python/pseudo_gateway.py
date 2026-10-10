"""Client Python pour la passerelle de pseudonymisation.

Sans dépendance : seulement la bibliothèque standard, pour qu'un copier-coller
suffise. Avec `requests` ou `httpx`, la logique est la même.

    from pseudo_gateway import PseudoGateway

    gw = PseudoGateway("https://votre-domaine", "pgw_votre_cle")

    propre = gw.pseudonymize("Marie Dupont (marie@exemple.fr) a signé.")
    print(propre.text)        # [PERSON_1] ([EMAIL_1]) a signé.

    reponse_du_llm = appeler_votre_llm(propre.text)
    print(gw.depseudonymize(reponse_du_llm))
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class PseudoGatewayError(RuntimeError):
    """Erreur renvoyée par la passerelle.

    `code` reprend le champ `error` de la réponse (`unauthorized`,
    `quota_exceeded`…) : c'est lui qu'il faut tester, pas le message, qui est
    destiné aux humains.
    """

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"[{status} {code}] {message}")
        self.status = status
        self.code = code
        self.message = message


@dataclass
class Pseudonymized:
    """Texte prêt à partir vers le LLM, et jetons qu'il contient.

    Attention : `tokens` liste les jetons **sans crochets** (`"EMAIL_1"`), alors
    que le texte les écrit entre crochets (`"[EMAIL_1]"`). C'est la forme entre
    crochets qu'il faut renvoyer à `depseudonymize` ; `bracketed` la donne.
    """

    text: str
    tokens: list[str] = field(default_factory=list)

    @property
    def bracketed(self) -> list[str]:
        """Les jetons tels qu'ils apparaissent dans le texte : `["[EMAIL_1]"]`."""
        return [f"[{t}]" for t in self.tokens]


class PseudoGateway:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        tenant_id: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 2,
    ):
        """`tenant_id` cloisonne les jetons à l'intérieur de votre compte, par
        exemple un espace par dossier client. Les jetons créés sous un tenant ne
        sont restituables que sous le même tenant.
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.timeout = timeout
        self.max_retries = max_retries

    def pseudonymize(
        self, text: str, custom_terms: list[tuple[str, str]] | None = None
    ) -> Pseudonymized:
        """Remplace les données sensibles par des jetons réversibles.

        `custom_terms` ajoute des termes que la détection automatique ignore,
        sous la forme `[("ORG", "JohnTech")]` — utile pour les noms de société.
        """
        payload: dict = {"text": text}
        if custom_terms:
            payload["custom_terms"] = [{"type": t, "value": v} for t, v in custom_terms]
        data = self._post("/v1/pseudonymize", payload)
        return Pseudonymized(text=data["text"], tokens=data.get("tokens", []))

    def depseudonymize(self, text: str) -> str:
        """Restitue les valeurs réelles d'un texte contenant des jetons.

        Un jeton inconnu est laissé tel quel : la méthode ne lève pas d'erreur.
        """
        return self._post("/v1/depseudonymize", {"text": text})["text"]

    def me(self) -> dict:
        """Compte associé à la clé et consommation du mois."""
        return self._request("GET", "/v1/me", None)

    # ── interne ──────────────────────────────────────────────────────────

    def _post(self, path: str, payload: dict) -> dict:
        if self.tenant_id:
            payload = {**payload, "tenant_id": self.tenant_id}
        return self._request("POST", path, payload)

    def _request(self, method: str, path: str, payload: dict | None) -> dict:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        for essai in range(self.max_retries + 1):
            req = urllib.request.Request(f"{self.base_url}{path}", data=body, method=method)
            req.add_header("X-Api-Key", self.api_key)
            if body is not None:
                # charset=utf-8 : le corps doit être en UTF-8, comme l'exige JSON.
                req.add_header("Content-Type", "application/json; charset=utf-8")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                status = e.code
                detail = e.read().decode("utf-8", "replace")
                try:
                    erreur = json.loads(detail)
                    code, message = erreur.get("error", ""), erreur.get("message", detail)
                except json.JSONDecodeError:
                    code, message = "", detail
                # 429 : quota mensuel épuisé (inutile de réessayer) ou limite par
                # minute (Retry-After dit quand revenir).
                attente = e.headers.get("Retry-After")
                if status == 429 and attente and essai < self.max_retries:
                    time.sleep(min(float(attente), 60.0))
                    continue
                raise PseudoGatewayError(status, code, message) from None
        raise PseudoGatewayError(429, "rate_limited", "limite atteinte après plusieurs essais")
