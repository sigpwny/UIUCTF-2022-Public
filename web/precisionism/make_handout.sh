tar --owner="arx" --group="arx" \
    --transform 's|^ism-bot/challenge/bot.js|ism-bot/bot.js|' \
    --transform 's|^challenge|precisionism|' \
    -czvf handout.tar.gz challenge ../ism-bot/challenge/bot.js
