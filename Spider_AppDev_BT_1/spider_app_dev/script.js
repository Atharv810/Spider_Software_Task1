let players = [
    {
        name: "You",
        lives: 3,
        isBot: false
    },
    {
        name: "Bot 1",
        lives: 3,
        isBot: true
    },
    {
        name: "Bot 2",
        lives: 3,
        isBot: true
    }
];

const submitBtn = document.getElementById("submitBtn");

submitBtn.addEventListener("click", playRound);

function playRound() {

    const userNumber =
        Number(document.getElementById("userInput").value);

    if (userNumber < 0 || userNumber > 100 || isNaN(userNumber)) {
        alert("Enter a number between 0 and 100");
        return;
    }

    let choices = [];

    for (let player of players) {

        if (player.lives <= 0) continue;

        if (player.isBot) {
            choices.push({
                player: player,
                number: Math.floor(Math.random() * 101)
            });
        } else {
            choices.push({
                player: player,
                number: userNumber
            });
        }
    }

    let total = 0;

    for (let choice of choices) {
        total += choice.number;
    }

    const average = total / choices.length;
    const targetNumber = average * 0.8;

    let winner = choices[0];
    let smallestDifference =
        Math.abs(choices[0].number - targetNumber);

    for (let choice of choices) {

        let difference =
            Math.abs(choice.number - targetNumber);

        if (difference < smallestDifference) {
            smallestDifference = difference;
            winner = choice;
        }
    }

    for (let choice of choices) {
        if (choice.player !== winner.player) {
            choice.player.lives--;
        }
    }

    updateLives();

    displayResults(
        choices,
        targetNumber,
        winner.player.name
    );

    checkGameEnd();
}

function updateLives() {

    document.getElementById("userLives").textContent =
        players[0].lives;

    document.getElementById("bot1Lives").textContent =
        players[1].lives;

    document.getElementById("bot2Lives").textContent =
        players[2].lives;
}

function displayResults(
    choices,
    targetNumber,
    winnerName
) {

    let html = "<h3>Round Results</h3>";

    choices.forEach(choice => {
        html += `
            <p>
                ${choice.player.name} chose
                ${choice.number}
            </p>
        `;
    });

    html += `
        <p>
            Target Number:
            ${targetNumber.toFixed(2)}
        </p>

        <p>
            Winner:
            ${winnerName}
        </p>
    `;

    document.getElementById("result").innerHTML = html;
}

function checkGameEnd() {

    const user = players[0];

    if (user.lives <= 0) {
        alert("Game Over");
        submitBtn.disabled = true;
        return;
    }

    const alivePlayers =
        players.filter(player => player.lives > 0);

    if (
        alivePlayers.length === 1 &&
        alivePlayers[0].name === "You"
    ) {
        alert("Victory!");
        submitBtn.disabled = true;
    }
}