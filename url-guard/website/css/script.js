
document.addEventListener("DOMContentLoaded", () => {

    const form = document.querySelector("form");
    const input = document.querySelector("input");
    const output = document.getElementById("out");

    const colors = {
        Safe: "var(--safe)",
        Suspicious: "var(--warn)",
        Dangerous: "var(--bad)"
    };

    form.addEventListener("submit", (e) => {

        e.preventDefault();

        // Analyze URL using detector.js
        const result = URLGuard.analyze(input.value);

        // Show results
        output.hidden = false;

        // Display verdict
        const verdict = document.getElementById("verdict");

        verdict.textContent = result.verdict;
        verdict.style.color = colors[result.verdict] || "var(--ink)";

        // Display risk score and URL
        document.getElementById("meta").textContent =
            "Risk score " + result.score + " for " + result.url;

        // Display detected rules
        const list = document.getElementById("rules");

        list.innerHTML = "";

        const hits = result.hits.length
            ? result.hits
            : [{ label: "No warning signs found", weight: 0 }];

        hits.forEach((hit) => {

            const li = document.createElement("li");

            const label = document.createElement("span");
            const weight = document.createElement("b");

            label.textContent = hit.label;
            weight.textContent = "+" + hit.weight;

            li.append(label, weight);

            list.appendChild(li);

        });

        // Bring results into view
        output.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        });

    });

});
