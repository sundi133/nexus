# Asset management

Keep track of the hardware your organization owns, whether or not it runs the Nexus agent: laptops, phones, monitors, network gear. Open **Devices → Assets**.

## Records

Each asset has:

- an **asset tag** (unique, like the sticker);
- a kind, make, model and serial number;
- a status: **in stock**, **assigned**, **in repair**, **retired** or **lost**;
- a location, vendor, purchase date and cost, warranty end date, and notes.

**Enrolled devices are matched by serial number** (ignoring case and spaces), so an asset shows the device it is, and links to it. **Add enrolled devices** creates a record for every enrolled device that doesn't have one yet, assigned to the device's current user.

## Checking out and in

- **Check out** gives an asset to someone.
- **Check in** takes it back: to stock, for repair, retired, or reported lost.

Each step is kept in the asset's history (who had it, when, who handed it over, and a note) and audited (`asset.checked_out`, `asset.checked_in`). To keep an asset's history, retire it instead of deleting it.

## Offboarding

The offboarding preview lists the hardware checked out to the person. When they're offboarded, owners, admins and helpdesk get a **Collect…** notification naming their enrolled devices and assets. Their assets stay assigned to them, flagged **left: collect**, until someone checks them in.

## Importing

**Import** takes a CSV with a header row. Existing tags are updated and new ones added. The columns are:

```
tag,name,kind,make,model,serial,location,vendor,purchase_date,purchase_cost,currency,warranty_until,notes,assigned_to_email
```

Only `tag` is required. Dates are `YYYY-MM-DD`. An `assigned_to_email` that matches someone in Nexus marks the asset as theirs; anything that can't be imported is listed by row.

## At a glance

- how many assets are assigned or in stock;
- how many are still with people who've left;
- warranties ending in the next 90 days;
- the purchase value of what's in service;
- enrolled devices without an asset record.

## API

`GET`/`POST /v1/assets`, `GET`/`PUT`/`DELETE /v1/assets/{id}`, `POST /v1/assets/{id}/checkout`, `POST /v1/assets/{id}/checkin`, `POST /v1/assets/import` and `POST /v1/assets/from-devices`. Reading needs `devices:read`; changes need `devices:write`.

## Limits

- **No depreciation or accounting.** Export to your finance tools for that.
- **No barcode scanning or procurement.**
