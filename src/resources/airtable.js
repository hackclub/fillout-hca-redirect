let { token } = input.config();

let response = await fetch("{SCHEMA}://{BASE_URL}/fields", {
  headers: {
    Authorization: "Bearer " + token,
    "ngrok-skip-browser-warning": "1",
  },
});

if (!response.ok) {
  throw new Error("/fields returned " + response.status);
}

let fields = await response.json();

output.set("first_name", fields.first_name);
output.set("last_name", fields.last_name);
output.set("email", fields.email);
output.set("address_line_1", fields.address_line_1);
output.set("address_line_2", fields.address_line_2);
output.set("city", fields.city);
output.set("state", fields.state);
output.set("country", fields.country);
output.set("postal_code", fields.postal_code);
output.set("birthday", fields.birthday);
output.set("phone", fields.phone);
output.set("ysws_eligible", fields.ysws_eligible);
