# Hack Club Fillout HCA Redirect

This allows a YSWS program to have a button on their submission Fillout form that reads `Continue with Hack Club`. After the user logs in and submits the form, the following fields in Airtable will be automatically populated:

- First Name
- Last Name
- Email
- Address Line 1
- Address Line 2
- City
- State
- Country
- Postal Code
- Birthday
- Phone Number
- YSWS Eligible

# Setup instructions

First, we will create the button in Fillout. Insert the HTML element at Other > Navigation & Layout > HTML. Enable `Allow scripts and iframes`, disable `Advanced > Render in iframe`, then copy-paste the following into the HTML field:

```html
<script>
  ((u, D = document) => {
    const w = setInterval(() => {
      const c = D.querySelector(".fillout-field-html");
      if (!c) return;
      clearInterval(w);
      fetch(u)
        .then((r) => r.text())
        .then((t) => {
          const d = D.createElement("div");
          d.innerHTML = t;
          d.querySelectorAll("script").forEach((o) =>
            o.replaceWith(
              Object.assign(D.createElement("script"), {
                textContent: o.textContent,
              }),
            ),
          );
          c.appendChild(d);
          new MutationObserver(() => c.contains(d) || c.appendChild(d)).observe(
            c,
            { childList: 1 },
          );
        });
    }, 100);
  })("https://fillout-hca-redirect.hackclub.com/button");
</script>
```

Afterwards, create a Short Answer element whose name _must_ be exactly `token`. You should make this always hidden with `Logic > Hide Always`. Hook it up to a field in your Airtable submission table that is also named `token`.

Finally, we have to set up an automation within Airtable that will redeem that opaque token and populate the fields. First, add a "When a record is created" trigger (or whatever else you want). Next, add a "Run a script" action. Set the token to the token from the trigger and for the script, copy-paste the content from [https://fillout-hca-redirect.hackclub.com/airtable](https://fillout-hca-redirect.hackclub.com/airtable). Finally, add an "Update record" action pointed to the Trigger's Airtable record ID. You will have to match up all of the fields that you would like filled in from the output values of the script.

You may wish to still ask the user for their email outside of this flow. In the event that the automated systems fail, this will allow you to track down the user either through email or through Slack (`/se info EMAIL`).

The session expires ten minutes after the user logs in. If you have an especially long form, this may bite you. This could be put at the end of the form, though keep in mind that this flow involves going off then back on the page so you will need to enable answer persistence for this to work.

# Building server from source
```bash
cargo build --release
```
