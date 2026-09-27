/**
 * The SaaS catalog, as text: "## Category" headings, then one app per line, "Name: host host…".
 * A host matches itself and its subdomains. Hosts are where people use the app (and sign in),
 * not marketing sites shared with other products. Every host was checked in DNS: the few that
 * don't resolve on their own are tenant suffixes (acme.jamfcloud.com, x.my.salesforce.com).
 */
export const DATA = `
## Collaboration
Slack: slack.com
Microsoft Teams: teams.microsoft.com teams.live.com
Zoom: zoom.us
Google Meet: meet.google.com
Webex: webex.com
GoTo Meeting: goto.com gotomeeting.com
RingCentral: ringcentral.com
Discord: discord.com
Rocket.Chat Cloud: cloud.rocket.chat
Chanty: chanty.com
Flock: flock.com
Twist: twist.com
Pumble: pumble.com
Zulip Cloud: zulipchat.com
Element: app.element.io
Wire: app.wire.com
Workplace from Meta: workplace.com
Loom: loom.com
Vidyard: vidyard.com
Around: around.co
Whereby: whereby.com
Dialpad: dialpad.com
Aircall: aircall.io
8x8: 8x8.com
Vonage: vonage.com
Nextiva: nextiva.com
Grasshopper: grasshopper.com
Gather: gather.town
Livestorm: livestorm.co
Hopin: hopin.com
Airmeet: airmeet.com
Riverside: riverside.fm
StreamYard: streamyard.com
Restream: restream.io
Calendly: calendly.com
Doodle: doodle.com
Cal.com: cal.com
SavvyCal: savvycal.com
Chili Piper: chilipiper.com
YouCanBookMe: youcanbook.me
Acuity Scheduling: acuityscheduling.com
Microsoft Bookings: outlook.office.com/bookings
Slido: slido.com
Mentimeter: mentimeter.com
Poll Everywhere: polleverywhere.com
Kahoot!: kahoot.com kahoot.it
Mural: mural.co app.mural.co
Miro: miro.com
FigJam: figma.com/figjam
Lucid: lucid.app lucidchart.com
Whimsical: whimsical.com
Excalidraw+: plus.excalidraw.com
tldraw: tldraw.com
Conceptboard: conceptboard.com
Stormboard: stormboard.com
Padlet: padlet.com
Workvivo: workvivo.com
Staffbase: staffbase.com
Simpplr: simpplr.com
LumApps: lumapps.com
Happeo: happeo.com
Unily: unily.com
Guru: getguru.com
Tettra: tettra.com
Slab: slab.com
Nuclino: nuclino.com
Almanac: almanac.io
Threads: threads.com
Front: frontapp.com
Missive: missiveapp.com
Superhuman: superhuman.com
Spark Mail: sparkmailapp.com
Hey: hey.com
Shortwave: shortwave.com

## Email and calendar
Gmail: mail.google.com
Google Calendar: calendar.google.com
Outlook on the web: outlook.office.com outlook.office365.com outlook.live.com
Yahoo Mail: mail.yahoo.com
Proton Mail: mail.proton.me
Zoho Mail: mail.zoho.com
Fastmail: fastmail.com app.fastmail.com
iCloud Mail: icloud.com
Mailchimp Transactional: mandrillapp.com
Clean Email: clean.email
Reclaim.ai: reclaim.ai
Motion: usemotion.com
Clockwise: getclockwise.com
Fantastical: fantastical.app
Vimcal: vimcal.com
Amie: amie.so

## Documents and files
Google Drive: drive.google.com
Google Docs: docs.google.com
Microsoft SharePoint: sharepoint.com
Microsoft OneDrive: onedrive.live.com
Microsoft 365: office.com microsoft365.com
Dropbox: dropbox.com
Box: box.com app.box.com
Egnyte: egnyte.com
Citrix ShareFile: sharefile.com
pCloud: pcloud.com
Sync.com: sync.com
Tresorit: tresorit.com
Proton Drive: drive.proton.me
MEGA: mega.nz mega.io
WeTransfer: wetransfer.com
Hightail: hightail.com
Smash: fromsmash.com
Filestage: filestage.io
Frame.io: frame.io
Wistia: wistia.com
Vimeo: vimeo.com
Brandfolder: brandfolder.com
Bynder: bynder.com
Canto: canto.com
Air: air.inc
Pics.io: pics.io
Notion: notion.so notion.com
Coda: coda.io
Quip: quip.com
Dropbox Paper: paper.dropbox.com
Confluence: atlassian.net/wiki
Zoho WorkDrive: workdrive.zoho.com
Zoho Writer: writer.zoho.com
Evernote: evernote.com
OneNote: onenote.com
Obsidian Sync: obsidian.md
Roam Research: roamresearch.com
Craft: craft.do
Bear: bear.app
Mem: mem.ai
Reflect: reflect.app
Capacities: capacities.io
Anytype: anytype.io
Logseq: logseq.com
Scribe: scribehow.com
Tango: tango.us
Guidde: guidde.com
Document360: document360.com
GitBook: gitbook.com
ReadMe: readme.com
Archbee: archbee.com
Mintlify: mintlify.com
Docusaurus Cloud: docusaurus.io
Helpjuice: helpjuice.com
Bloomfire: bloomfire.com
Papyrs: papyrs.com
Adobe Acrobat: acrobat.adobe.com documentcloud.adobe.com
Smallpdf: smallpdf.com
iLovePDF: ilovepdf.com
PDFfiller: pdffiller.com
Foxit Cloud: foxit.com
Nitro: gonitro.com
Kami: kamiapp.com
Pitch: pitch.com
Gamma: gamma.app
Beautiful.ai: beautiful.ai
Prezi: prezi.com
Google Slides: slides.google.com
Canva: canva.com
Visme: visme.co
Genially: genial.ly
Tome: tome.app
Ludus: ludus.one
Slidebean: slidebean.com
Zoho Show: show.zoho.com

## E-signature and contracts
DocuSign: docusign.com docusign.net
Adobe Acrobat Sign: adobesign.com echosign.com
Dropbox Sign: sign.dropbox.com hellosign.com
PandaDoc: pandadoc.com
SignNow: signnow.com
Juro: juro.com
Ironclad: ironcladapp.com
ContractPodAi: contractpodai.com
LinkSquares: linksquares.com
Agiloft: agiloft.com
Icertis: icertis.com
Conga: conga.com
SpotDraft: spotdraft.com
Concord: concordnow.com
Zoho Sign: sign.zoho.com
SignWell: signwell.com
Yousign: yousign.com
OneFlow: oneflow.com
Proposify: proposify.com
Qwilr: qwilr.com
Better Proposals: betterproposals.io
Clio: clio.com app.clio.com
MyCase: mycase.com
PracticePanther: practicepanther.com
Smokeball: smokeball.com
Rocket Lawyer: rocketlawyer.com
LegalZoom: legalzoom.com
Everlaw: everlaw.com
Relativity: relativity.com
Logikcull: logikcull.com
Harvey: harvey.ai
Spellbook: spellbook.legal
Evisort: evisort.com

## Project management
Jira: atlassian.net atlassian.com
Asana: asana.com app.asana.com
Trello: trello.com
monday.com: monday.com
ClickUp: clickup.com app.clickup.com
Linear: linear.app
Wrike: wrike.com
Smartsheet: smartsheet.com app.smartsheet.com
Airtable: airtable.com
Basecamp: basecamp.com 3.basecamp.com
Teamwork.com: teamwork.com
Todoist: todoist.com
TickTick: ticktick.com
Things Cloud: culturedcode.com
Microsoft Planner: tasks.office.com planner.cloud.microsoft
Microsoft To Do: to-do.office.com to-do.live.com
Google Tasks: tasks.google.com
Height: height.app
Shortcut: shortcut.com app.shortcut.com
YouTrack: youtrack.cloud
Plane: plane.so
Taiga: taiga.io
Zenhub: zenhub.com app.zenhub.com
Productboard: productboard.com
Aha!: aha.io
ProdPad: prodpad.com
Canny: canny.io
Featurebase: featurebase.app
UserVoice: uservoice.com
Nolt: nolt.io
Pendo: pendo.io
Roadmunk: roadmunk.com
Targetprocess: targetprocess.com
Rally: rallydev.com
Planview: planview.com
Adobe Workfront: workfront.com my.workfront.com
Workamajig: workamajig.com
Teamwork Desk: teamwork.com/desk
Hive: hive.com
nTask: ntaskmanager.com
MeisterTask: meistertask.com
MindMeister: mindmeister.com
Miro Lite: lite.miro.com
Notion Calendar: calendar.notion.so
Kantata: kantata.com
Mavenlink: mavenlink.com
Float: float.com app.float.com
Resource Guru: resourceguruapp.com
Forecast: forecast.app
Runn: runn.io
Teamdeck: teamdeck.io
Toggl Plan: toggl.com/plan
Toggl Track: track.toggl.com toggl.com
Harvest: harvestapp.com getharvest.com
Clockify: clockify.me
Everhour: everhour.com
Timely: timelyapp.com
Hubstaff: hubstaff.com app.hubstaff.com
Time Doctor: timedoctor.com
RescueTime: rescuetime.com
Tempo: tempo.io
Scoro: scoro.com
Productive: productive.io
Accelo: accelo.com
Paymo: paymoapp.com
Zoho Projects: projects.zoho.com
Celoxis: celoxis.com
GanttPRO: ganttpro.com
TeamGantt: teamgantt.com
Instagantt: instagantt.com
Office Timeline: officetimeline.com
Nifty: niftypm.com
Workzone: workzone.com
Quickbase: quickbase.com
Fibery: fibery.io
Tability: tability.io
Lattice Goals: lattice.com/goals
Perdoo: perdoo.com
Weekdone: weekdone.com
Quantive: quantive.com
Range: range.co
Geekbot: geekbot.com
Standuply: standuply.com
Status Hero: statushero.com
Fellow: fellow.app
Hypercontext: hypercontext.com
Spinach: spinach.io
Otter.ai: otter.ai
Fireflies.ai: fireflies.ai
Fathom: fathom.video
Grain: grain.com
tl;dv: tldv.io
Avoma: avoma.com
Read AI: read.ai
Krisp: krisp.ai
Descript: descript.com
Rev: rev.com
Trint: trint.com
Sonix: sonix.ai
Happy Scribe: happyscribe.com

## Engineering
GitHub: github.com
GitLab: gitlab.com
Bitbucket: bitbucket.org
Azure DevOps: dev.azure.com visualstudio.com
AWS CodeCatalyst: codecatalyst.aws
Gitea Cloud: gitea.com
SourceHut: sr.ht
Codeberg: codeberg.org
Replit: replit.com
CodeSandbox: codesandbox.io
StackBlitz: stackblitz.com
Glitch: glitch.com
CodePen: codepen.io
JSFiddle: jsfiddle.net
Gitpod: gitpod.io
GitHub Codespaces: github.dev
Coder: coder.com
Sourcegraph: sourcegraph.com
Tabnine: tabnine.com
Codeium: codeium.com
Windsurf: windsurf.com
Cursor: cursor.com
Sourcery: sourcery.ai
CodeRabbit: coderabbit.ai
Graphite: graphite.dev app.graphite.dev
Reviewable: reviewable.io
Codacy: codacy.com app.codacy.com
SonarCloud: sonarcloud.io
DeepSource: deepsource.com app.deepsource.com
Code Climate: codeclimate.com
Snyk: snyk.io app.snyk.io
Socket: socket.dev
Semgrep: semgrep.dev
GitGuardian: gitguardian.com dashboard.gitguardian.com
Mend: mend.io
Checkmarx: checkmarx.net checkmarx.com
Veracode: veracode.com
Black Duck: blackduck.com
FOSSA: fossa.com app.fossa.com
Dependabot: dependabot.com
Renovate: mend.io/renovate
Postman: postman.com
Insomnia: insomnia.rest
Hoppscotch: hoppscotch.io
Stoplight: stoplight.io
SwaggerHub: swaggerhub.com
Apiary: apiary.io
RapidAPI: rapidapi.com
Kong Konnect: konghq.com cloud.konghq.com
Apigee: apigee.com
Tyk Cloud: tyk.io
Readme.io: readme.io
Bump.sh: bump.sh
Mockoon Cloud: mockoon.com
Beeceptor: beeceptor.com
ngrok: ngrok.com dashboard.ngrok.com
LocalXpose: localxpose.io
Tailscale: tailscale.com login.tailscale.com
ZeroTier: zerotier.com my.zerotier.com
Twingate: twingate.com
Teleport: goteleport.com
StrongDM: strongdm.com app.strongdm.com
Warp: warp.dev
Fig: fig.io
Termius: termius.com
Jam: jam.dev
Loom for Engineering: loom.com/engineering
Sentry: sentry.io
Bugsnag: bugsnag.com app.bugsnag.com
Rollbar: rollbar.com
Raygun: raygun.com app.raygun.com
Honeybadger: honeybadger.io
Airbrake: airbrake.io
LogRocket: logrocket.com app.logrocket.com
FullStory: fullstory.com app.fullstory.com
Hotjar: hotjar.com insights.hotjar.com
Smartlook: smartlook.com
Microsoft Clarity: clarity.microsoft.com
Mouseflow: mouseflow.com
Crazy Egg: crazyegg.com
Heap: heap.io heapanalytics.com
Mixpanel: mixpanel.com
Amplitude: amplitude.com app.amplitude.com
PostHog: posthog.com us.posthog.com eu.posthog.com
Segment: segment.com app.segment.com
RudderStack: rudderstack.com app.rudderstack.com
mParticle: mparticle.com
Snowplow: snowplow.io
June: june.so
Statsig: statsig.com console.statsig.com
LaunchDarkly: launchdarkly.com app.launchdarkly.com
Split: split.io app.split.io
Flagsmith: flagsmith.com app.flagsmith.com
ConfigCat: configcat.com app.configcat.com
Unleash: getunleash.io
Optimizely: optimizely.com app.optimizely.com
VWO: vwo.com app.vwo.com
AB Tasty: abtasty.com
Kameleoon: kameleoon.com
Eppo: geteppo.com
GrowthBook: growthbook.io app.growthbook.io
BrowserStack: browserstack.com
Sauce Labs: saucelabs.com
LambdaTest: lambdatest.com
Cypress Cloud: cypress.io cloud.cypress.io
Playwright Testing: playwright.microsoft.com
Percy: percy.io
Chromatic: chromatic.com
Applitools: applitools.com
Testim: testim.io
mabl: mabl.com app.mabl.com
Rainforest QA: rainforestqa.com
QA Wolf: qawolf.com
Ghost Inspector: ghostinspector.com
TestRail: testrail.com
Zephyr: smartbear.com/test-management
Xray: getxray.app
qTest: tricentis.com
Qase: qase.io app.qase.io
Testmo: testmo.com
PractiTest: practitest.com
Katalon: katalon.com
Tricentis Tosca: tricentis.com/products/automate-continuous-testing-tosca
Storybook Chromatic: storybook.js.org
Bit.cloud: bit.cloud
npm: npmjs.com
PyPI: pypi.org
Docker Hub: hub.docker.com docker.com
JFrog: jfrog.io jfrog.com
Sonatype Nexus Cloud: sonatype.com
Cloudsmith: cloudsmith.io cloudsmith.com
Packagecloud: packagecloud.io
Gemfury: gemfury.com
Anaconda: anaconda.com anaconda.org
Hugging Face: huggingface.co
Kaggle: kaggle.com
Weights & Biases: wandb.ai
Comet: comet.com
Neptune: neptune.ai
DagsHub: dagshub.com
Roboflow: roboflow.com app.roboflow.com
Labelbox: labelbox.com app.labelbox.com
Scale AI: scale.com dashboard.scale.com
Snorkel: snorkel.ai
Replicate: replicate.com
Modal: modal.com
Baseten: baseten.co
Together AI: together.ai api.together.ai
Fireworks AI: fireworks.ai
Groq Cloud: console.groq.com groq.com
OpenAI Platform: platform.openai.com
Anthropic Console: console.anthropic.com
Google AI Studio: aistudio.google.com
Azure OpenAI: oai.azure.com ai.azure.com
Cohere: cohere.com dashboard.cohere.com
Pinecone: pinecone.io app.pinecone.io
Weaviate Cloud: weaviate.io console.weaviate.cloud
Qdrant Cloud: qdrant.tech cloud.qdrant.io
LangSmith: smith.langchain.com
Langfuse: langfuse.com cloud.langfuse.com
Helicone: helicone.ai
Humanloop: humanloop.com
Vellum: vellum.ai app.vellum.ai
Braintrust: braintrust.dev
Arize: arize.com app.arize.com
Retool: retool.com
Appsmith: appsmith.com app.appsmith.com
Budibase: budibase.com
ToolJet: tooljet.com
Superblocks: superblocks.com app.superblocks.com
Internal.io: internal.io
Bubble: bubble.io
Webflow: webflow.com
Framer: framer.com
Softr: softr.io
Glide: glideapps.com
Adalo: adalo.com
FlutterFlow: flutterflow.io app.flutterflow.io
Draftbit: draftbit.com
Thunkable: thunkable.com
AppSheet: appsheet.com
Microsoft Power Apps: powerapps.com make.powerapps.com
Microsoft Power Automate: powerautomate.com make.powerautomate.com
Zapier: zapier.com
Make: make.com
n8n Cloud: n8n.io app.n8n.cloud
Workato: workato.com app.workato.com
Tray.io: tray.io app.tray.io
Pipedream: pipedream.com
IFTTT: ifttt.com
Integromat: integromat.com
Celigo: celigo.com integrator.io
Boomi: boomi.com platform.boomi.com
MuleSoft: mulesoft.com anypoint.mulesoft.com
SnapLogic: snaplogic.com
Jitterbit: jitterbit.com
Unito: unito.io app.unito.io
Relay.app: relay.app
Bardeen: bardeen.ai
Parabola: parabola.io
Airplane: airplane.dev
Val Town: val.town
Supabase: supabase.com
Firebase: firebase.google.com console.firebase.google.com
Appwrite Cloud: appwrite.io cloud.appwrite.io
Convex: convex.dev dashboard.convex.dev
Nhost: nhost.io
Xata: xata.io app.xata.io
Neon: neon.tech console.neon.tech
PlanetScale: planetscale.com app.planetscale.com
CockroachDB Cloud: cockroachlabs.cloud cockroachlabs.com
MongoDB Atlas: cloud.mongodb.com mongodb.com
Redis Cloud: redis.io app.redislabs.com
Upstash: upstash.com console.upstash.com
Aiven: aiven.io console.aiven.io
Timescale: timescale.com console.cloud.timescale.com
ClickHouse Cloud: clickhouse.cloud clickhouse.com
SingleStore: singlestore.com portal.singlestore.com
Couchbase Capella: couchbase.com cloud.couchbase.com
Fauna: fauna.com
Turso: turso.tech app.turso.tech
Elastic Cloud: elastic.co cloud.elastic.co
Algolia: algolia.com dashboard.algolia.com
Typesense Cloud: typesense.org cloud.typesense.org
Meilisearch Cloud: meilisearch.com cloud.meilisearch.com
Contentful: contentful.com app.contentful.com
Sanity: sanity.io
Strapi Cloud: strapi.io cloud.strapi.io
Storyblok: storyblok.com app.storyblok.com
Prismic: prismic.io
DatoCMS: datocms.com
Hygraph: hygraph.com app.hygraph.com
Builder.io: builder.io
Payload Cloud: payloadcms.com
Ghost: ghost.org ghost.io
WordPress.com: wordpress.com
Squarespace: squarespace.com
Wix: wix.com manage.wix.com
Weebly: weebly.com
Duda: duda.co
Carrd: carrd.co
Umso: umso.com
Unbounce: unbounce.com app.unbounce.com
Leadpages: leadpages.com
Instapage: instapage.com
Typedream: typedream.com
Super.so: super.so
Dorik: dorik.com
Hostinger: hostinger.com hpanel.hostinger.com
GoDaddy: godaddy.com
Namecheap: namecheap.com
Porkbun: porkbun.com
Gandi: gandi.net
Hover: hover.com
Squarespace Domains: domains.squarespace.com
Name.com: name.com
Dynadot: dynadot.com
IONOS: ionos.com

## Cloud and infrastructure
Amazon Web Services: console.aws.amazon.com signin.aws.amazon.com awsapps.com
Google Cloud: console.cloud.google.com cloud.google.com
Microsoft Azure: portal.azure.com azure.com
Oracle Cloud: cloud.oracle.com oraclecloud.com
IBM Cloud: cloud.ibm.com
Alibaba Cloud: alibabacloud.com
DigitalOcean: cloud.digitalocean.com digitalocean.com
Linode: cloud.linode.com linode.com
Vultr: my.vultr.com vultr.com
Hetzner: console.hetzner.cloud hetzner.com
OVHcloud: ovh.com ovhcloud.com
Scaleway: console.scaleway.com scaleway.com
UpCloud: upcloud.com hub.upcloud.com
Heroku: heroku.com dashboard.heroku.com
Render: render.com dashboard.render.com
Railway: railway.app railway.com
Fly.io: fly.io
Vercel: vercel.com
Netlify: netlify.com app.netlify.com
Cloudflare: dash.cloudflare.com cloudflare.com
Fastly: fastly.com manage.fastly.com
Akamai: akamai.com control.akamai.com
Bunny.net: bunny.net dash.bunny.net
KeyCDN: keycdn.com
Imperva: imperva.com
StackPath: stackpath.com
Sucuri: sucuri.net
Deno Deploy: deno.com dash.deno.com
Koyeb: koyeb.com app.koyeb.com
Northflank: northflank.com app.northflank.com
Porter: porter.run
Qovery: qovery.com console.qovery.com
Platform.sh: platform.sh console.platform.sh
Pantheon: pantheon.io dashboard.pantheon.io
WP Engine: wpengine.com my.wpengine.com
Kinsta: kinsta.com my.kinsta.com
Flywheel: getflywheel.com
Cloudways: cloudways.com platform.cloudways.com
SiteGround: siteground.com
Bluehost: bluehost.com
Acquia: acquia.com cloud.acquia.com
Terraform Cloud: app.terraform.io hashicorp.com
HashiCorp Cloud: portal.cloud.hashicorp.com
Pulumi Cloud: app.pulumi.com pulumi.com
Spacelift: spacelift.io
env0: env0.com app.env0.com
Scalr: scalr.com
Env0: env0.io
Doppler: doppler.com dashboard.doppler.com
Infisical: infisical.com app.infisical.com
Akeyless: akeyless.io console.akeyless.io
1Password Secrets Automation: developer.1password.com
CircleCI: circleci.com app.circleci.com
Travis CI: travis-ci.com app.travis-ci.com
Buildkite: buildkite.com
Semaphore: semaphoreci.com
Codefresh: codefresh.io g.codefresh.io
Harness: harness.io app.harness.io
Octopus Deploy: octopus.com octopus.app
Bitrise: bitrise.io app.bitrise.io
Codemagic: codemagic.io
Appcircle: appcircle.io
Depot: depot.dev
Earthly: earthly.dev
Nx Cloud: nx.app cloud.nx.app
Turborepo Remote Cache: turbo.build
Argo CD Cloud: akuity.io
Rancher Prime: rancher.com
Red Hat OpenShift: console.redhat.com openshift.com
Kubernetes Lens: k8slens.dev
Komodor: komodor.com app.komodor.com
Datadog: datadoghq.com datadoghq.eu app.datadoghq.com
New Relic: newrelic.com one.newrelic.com
Dynatrace: dynatrace.com live.dynatrace.com
AppDynamics: appdynamics.com
Grafana Cloud: grafana.com grafana.net
Honeycomb: honeycomb.io ui.honeycomb.io
Lightstep: lightstep.com app.lightstep.com
Chronosphere: chronosphere.io
Splunk Cloud: splunkcloud.com splunk.com
Sumo Logic: sumologic.com service.sumologic.com
Logz.io: logz.io app.logz.io
Papertrail: papertrailapp.com
Loggly: loggly.com
Better Stack: betterstack.com
Axiom: axiom.co app.axiom.co
Coralogix: coralogix.com
Mezmo: mezmo.com app.mezmo.com
Elastic Observability: elastic.co/observability
Checkly: checklyhq.com app.checklyhq.com
Pingdom: pingdom.com my.pingdom.com
UptimeRobot: uptimerobot.com
StatusCake: statuscake.com app.statuscake.com
Site24x7: site24x7.com
Statuspage: statuspage.io manage.statuspage.io
Instatus: instatus.com
PagerDuty: pagerduty.com
Opsgenie: opsgenie.com app.opsgenie.com
incident.io: incident.io app.incident.io
FireHydrant: firehydrant.com app.firehydrant.io
Rootly: rootly.com
Squadcast: squadcast.com app.squadcast.com
Splunk On-Call: victorops.com portal.victorops.com
xMatters: xmatters.com
Zenduty: zenduty.com
Cortex: cortex.io app.getcortexapp.com
OpsLevel: opslevel.com app.opslevel.com
Port: getport.io app.getport.io
Backstage Spotify Portal: backstage.spotify.com
Vantage: vantage.sh console.vantage.sh
CloudZero: cloudzero.com app.cloudzero.com
Kubecost: kubecost.com
Spot by NetApp: spot.io console.spotinst.com
CloudHealth: cloudhealthtech.com
Apptio Cloudability: cloudability.com app.apptio.com
ProsperOps: prosperops.com
nOps: nops.io

## Security
CrowdStrike Falcon: falcon.crowdstrike.com crowdstrike.com
SentinelOne: sentinelone.net sentinelone.com
Microsoft Defender: security.microsoft.com
Sophos Central: central.sophos.com sophos.com
Bitdefender GravityZone: gravityzone.bitdefender.com
ESET PROTECT: protect.eset.com
Trend Micro Vision One: xdr.trendmicro.com portal.xdr.trendmicro.com
Malwarebytes Nebula: cloud.malwarebytes.com
Huntress: huntress.com huntress.io
Arctic Wolf: arcticwolf.com
Rapid7: rapid7.com insight.rapid7.com
Tenable: tenable.com cloud.tenable.com
Qualys: qualys.com qualysguard.qualys.com
Wiz: wiz.io app.wiz.io
Orca Security: orca.security app.orcasecurity.io
Lacework: lacework.com lacework.net
Prisma Cloud: prismacloud.io paloaltonetworks.com
Palo Alto Networks: paloaltonetworks.com
Zscaler: zscaler.com zscaler.net
Netskope: netskope.com goskope.com
Cloudflare Zero Trust: one.dash.cloudflare.com cloudflareaccess.com
Cisco Umbrella: umbrella.cisco.com dashboard.umbrella.com
Cisco Duo: duosecurity.com duo.com
Okta: okta.com oktapreview.com
Auth0: auth0.com manage.auth0.com
OneLogin: onelogin.com
Ping Identity: pingidentity.com pingone.com
JumpCloud: jumpcloud.com console.jumpcloud.com
Microsoft Entra ID: entra.microsoft.com
Google Admin: admin.google.com
CyberArk: cyberark.com cyberark.cloud
BeyondTrust: beyondtrust.com beyondtrustcloud.com
Delinea: delinea.com secretservercloud.com
Keeper: keepersecurity.com
1Password: 1password.com
LastPass: lastpass.com
Bitwarden: bitwarden.com vault.bitwarden.com
Dashlane: dashlane.com app.dashlane.com
NordPass: nordpass.com
RoboForm: roboform.com
Zoho Vault: vault.zoho.com
Passbolt Cloud: passbolt.com
KnowBe4: knowbe4.com training.knowbe4.com
Proofpoint: proofpoint.com
Mimecast: mimecast.com
Abnormal Security: abnormalsecurity.com portal.abnormalsecurity.com
Material Security: material.security
Ironscales: ironscales.com
Avanan: avanan.com
Vanta: vanta.com app.vanta.com
Drata: drata.com app.drata.com
Secureframe: secureframe.com app.secureframe.com
Sprinto: sprinto.com app.sprinto.com
Thoropass: thoropass.com
Hyperproof: hyperproof.io
OneTrust: onetrust.com
TrustArc: trustarc.com
Osano: osano.com
Securiti: securiti.ai
BigID: bigid.com
Varonis: varonis.com
Cyera: cyera.io
Nightfall: nightfall.ai app.nightfall.ai
Island: island.io
Talon: talon-sec.com
LayerX: layerxsecurity.com
Push Security: pushsecurity.com
Grip Security: grip.security
Nudge Security: nudgesecurity.com
Abnormal AI Security Mailbox: abnormal.ai
Snyk Code: snyk.io/product/snyk-code
Aikido: aikido.dev app.aikido.dev
Chainguard: chainguard.dev console.chainguard.dev
Tines: tines.com tines.io
Torq: torq.io
Swimlane: swimlane.com
Panther: panther.com
Sumo Logic Cloud SIEM: sumologic.com/solutions/cloud-siem
Expel: expel.com workbench.expel.io
Red Canary: redcanary.com
HackerOne: hackerone.com
Bugcrowd: bugcrowd.com
Intigriti: intigriti.com app.intigriti.com
Cobalt: cobalt.io app.cobalt.io
Detectify: detectify.com
Intruder: intruder.io portal.intruder.io
Burp Suite Enterprise: portswigger.net
Recorded Future: recordedfuture.com app.recordedfuture.com
VirusTotal: virustotal.com
Shodan: shodan.io
SecurityScorecard: securityscorecard.com platform.securityscorecard.io
BitSight: bitsighttech.com service.bitsighttech.com
UpGuard: upguard.com cyber-risk.upguard.com
Whistic: whistic.com
Conveyor: conveyor.com app.conveyor.com
SafeBase: safebase.io
NordLayer: nordlayer.com
Perimeter 81: perimeter81.com
ExpressVPN: expressvpn.com
NordVPN: nordvpn.com
Surfshark: surfshark.com
Proton VPN: protonvpn.com account.protonvpn.com
Private Internet Access: privateinternetaccess.com

## IT and device management
Jamf: jamfcloud.com jamf.com
Kandji: kandji.io
Mosyle: mosyle.com business.mosyle.com
Addigy: addigy.com prod.addigy.com
Microsoft Intune: intune.microsoft.com endpoint.microsoft.com
VMware Workspace ONE: awmdm.com workspaceone.com
Ivanti: ivanti.com
Hexnode: hexnode.com
Scalefusion: scalefusion.com
Iru: iru.com
Fleet: fleetdm.com
Rippling IT: rippling.com/it
Automox: automox.com console.automox.com
NinjaOne: ninjaone.com app.ninjarmm.com
Kaseya VSA: kaseya.com
Datto RMM: datto.com
N-able: n-able.com
ConnectWise: connectwise.com
Atera: atera.com app.atera.com
Syncro: syncromsp.com
SuperOps: superops.com
Pulseway: pulseway.com
ManageEngine: manageengine.com
SolarWinds: solarwinds.com
PRTG: paessler.com
Auvik: auvik.com
Domotz: domotz.com
Meraki: meraki.cisco.com dashboard.meraki.com
Ubiquiti UniFi: unifi.ui.com ui.com
Aruba Central: arubanetworks.com
Juniper Mist: mist.com manage.mist.com
TeamViewer: teamviewer.com
AnyDesk: anydesk.com my.anydesk.com
Splashtop: splashtop.com my.splashtop.com
LogMeIn: logmein.com
GoTo Resolve: goto.com/it-management/resolve
RemotePC: remotepc.com
Chrome Remote Desktop: remotedesktop.google.com
Parsec: parsec.app
BeyondTrust Remote Support: beyondtrust.com/remote-support
ServiceNow: service-now.com servicenow.com
Jira Service Management: atlassian.net/jira/servicedesk
Freshservice: freshservice.com
Zendesk: zendesk.com
SysAid: sysaid.com
TOPdesk: topdesk.com
Ivanti Neurons: ivanticloud.com
HaloITSM: haloitsm.com
SolarWinds Service Desk: samanage.com
ManageEngine ServiceDesk Plus: sdpondemand.manageengine.com
Spiceworks: spiceworks.com
Siit: siit.io
Moveworks: moveworks.com
Aisera: aisera.com
Atomicwork: atomicwork.com
Serval: serval.com
Lumos: lumos.com app.lumos.com
Zluri: zluri.com app.zluri.com
Torii: toriihq.com app.toriihq.com
Productiv: productiv.com
BetterCloud: bettercloud.com app.bettercloud.com
Vendr: vendr.com app.vendr.com
Tropic: tropicapp.io app.tropicapp.io
Spendflo: spendflo.com
Cledara: cledara.com app.cledara.com
Snipe-IT Cloud: snipeitapp.com
Asset Panda: assetpanda.com
Lansweeper: lansweeper.com app.lansweeper.com
Oomnitza: oomnitza.com
Freshservice Asset: freshservice.com/asset-management
Device42: device42.com
Axonius: axonius.com
Firstbase: firstbase.com app.firstbase.io
Workwize: goworkwize.com
Hofy: hofy.com
Allwhere: allwhere.co
Electric: electric.ai
Printix: printix.net
PaperCut: papercut.com
Envoy: envoy.com dashboard.envoy.com
Robin: robinpowered.com dashboard.robinpowered.com
OfficeSpace: officespacesoftware.com
Skedda: skedda.com app.skedda.com
Deskbird: deskbird.com app.deskbird.com
Kisi: getkisi.com
Verkada: verkada.com command.verkada.com
Brivo: brivo.com
Openpath: openpath.com

## Design
Figma: figma.com
Sketch: sketch.com
Adobe Creative Cloud: creativecloud.adobe.com adobe.com
Adobe Express: express.adobe.com new.express.adobe.com
Adobe Firefly: firefly.adobe.com
InVision: invisionapp.com
Zeplin: zeplin.io app.zeplin.io
Abstract: abstract.com
Marvel: marvelapp.com
Proto.io: proto.io
Axure Cloud: axure.cloud axure.com
Balsamiq Cloud: balsamiq.cloud balsamiq.com
UXPin: uxpin.com
Penpot: penpot.app design.penpot.app
Spline: spline.design app.spline.design
Rive: rive.app
LottieFiles: lottiefiles.com
Maze: maze.co app.maze.co
UserTesting: usertesting.com
Lookback: lookback.io
Dovetail: dovetail.com dovetailapp.com
Optimal Workshop: optimalworkshop.com app.optimalworkshop.com
Useberry: useberry.com
Lyssna: lyssna.com
Great Question: greatquestion.co
User Interviews: userinterviews.com
Respondent: respondent.io app.respondent.io
Condens: condens.io
Marvin: heymarvin.com
Unsplash: unsplash.com
Shutterstock: shutterstock.com
Getty Images: gettyimages.com
Adobe Stock: stock.adobe.com
iStock: istockphoto.com
Envato Elements: elements.envato.com envato.com
Freepik: freepik.com
Pexels: pexels.com
Noun Project: thenounproject.com
Icons8: icons8.com
Flaticon: flaticon.com
Iconfinder: iconfinder.com
Coolors: coolors.co
Fontshare: fontshare.com
Adobe Fonts: fonts.adobe.com
Monotype Fonts: monotype.com
Remove.bg: remove.bg
Photopea: photopea.com
Pixlr: pixlr.com
Fotor: fotor.com
PicMonkey: picmonkey.com
Snappa: snappa.com
Crello: create.vista.com
Piktochart: piktochart.com
Infogram: infogram.com
Venngage: venngage.com
Flourish: flourish.studio app.flourish.studio
Datawrapper: datawrapper.de app.datawrapper.de
Midjourney: midjourney.com
Leonardo.Ai: leonardo.ai app.leonardo.ai
Ideogram: ideogram.ai
Runway: runwayml.com app.runwayml.com
Pika: pika.art
Luma AI: lumalabs.ai
Synthesia: synthesia.io app.synthesia.io
HeyGen: heygen.com app.heygen.com
D-ID: d-id.com studio.d-id.com
ElevenLabs: elevenlabs.io
Murf: murf.ai
Speechify: speechify.com
Suno: suno.com
Udio: udio.com
Kapwing: kapwing.com
Clipchamp: clipchamp.com app.clipchamp.com
VEED: veed.io
WeVideo: wevideo.com
InVideo: invideo.io
Animoto: animoto.com
Powtoon: powtoon.com
Vyond: vyond.com
Biteable: biteable.com
Camtasia Online: techsmith.com
Screencast-O-Matic: screencast-o-matic.com
ScreenPal: screenpal.com
Vidyard GoVideo: vidyard.com/govideo
Frame.io Cloud: next.frame.io
CapCut: capcut.com
Opus Clip: opus.pro clip.opus.pro

## Marketing
HubSpot: hubspot.com app.hubspot.com
Marketo: marketo.com marketo.net
Pardot: pardot.com
Mailchimp: mailchimp.com admin.mailchimp.com
Klaviyo: klaviyo.com
Braze: braze.com
Iterable: iterable.com app.iterable.com
Customer.io: customer.io fly.customer.io
Brevo: brevo.com app.brevo.com
Sendinblue: sendinblue.com
ActiveCampaign: activecampaign.com
Constant Contact: constantcontact.com
Campaign Monitor: campaignmonitor.com createsend.com
Kit: kit.com app.kit.com
ConvertKit: convertkit.com
MailerLite: mailerlite.com dashboard.mailerlite.com
Drip: drip.com
Omnisend: omnisend.com app.omnisend.com
GetResponse: getresponse.com app.getresponse.com
AWeber: aweber.com
Moosend: moosend.com
Beehiiv: beehiiv.com app.beehiiv.com
Substack: substack.com
Buttondown: buttondown.com
Loops: loops.so app.loops.so
SendGrid: sendgrid.com app.sendgrid.com
Mailgun: mailgun.com app.mailgun.com
Postmark: postmarkapp.com account.postmarkapp.com
Resend: resend.com
Twilio: twilio.com console.twilio.com
MessageBird: messagebird.com bird.com
Sinch: sinch.com dashboard.sinch.com
Plivo: plivo.com console.plivo.com
Attentive: attentivemobile.com ui.attentivemobile.com
Postscript: postscript.io app.postscript.io
OneSignal: onesignal.com dashboard.onesignal.com
Airship: airship.com go.airship.com
Pusher: pusher.com dashboard.pusher.com
Knock: knock.app dashboard.knock.app
Courier: courier.com app.courier.com
Novu: novu.co web.novu.co
Hootsuite: hootsuite.com
Sprout Social: sproutsocial.com app.sproutsocial.com
Buffer: buffer.com publish.buffer.com
Later: later.com app.later.com
Sprinklr: sprinklr.com
Agorapulse: agorapulse.com app.agorapulse.com
Loomly: loomly.com app.loomly.com
SocialBee: socialbee.com app.socialbee.com
Planoly: planoly.com
Brandwatch: brandwatch.com
Meltwater: meltwater.com app.meltwater.com
Cision: cision.com
Muck Rack: muckrack.com
Mention: mention.com
Talkwalker: talkwalker.com
Semrush: semrush.com
Ahrefs: ahrefs.com app.ahrefs.com
Moz: moz.com
SE Ranking: seranking.com online.seranking.com
Similarweb: similarweb.com
SpyFu: spyfu.com
Screaming Frog: screamingfrog.co.uk
Surfer: surferseo.com app.surferseo.com
Clearscope: clearscope.io
MarketMuse: marketmuse.com
Frase: frase.io app.frase.io
Jasper: jasper.ai app.jasper.ai
Copy.ai: copy.ai app.copy.ai
Writer: writer.com app.writer.com
Grammarly: grammarly.com app.grammarly.com
Wordtune: wordtune.com
QuillBot: quillbot.com
Hemingway Editor: hemingwayapp.com
ProWritingAid: prowritingaid.com
LanguageTool: languagetool.org
DeepL: deepl.com
Google Translate: translate.google.com
Smartling: smartling.com dashboard.smartling.com
Lokalise: lokalise.com app.lokalise.com
Phrase: phrase.com app.phrase.com
Crowdin: crowdin.com
Transifex: transifex.com app.transifex.com
Weglot: weglot.com dashboard.weglot.com
Google Analytics: analytics.google.com
Google Tag Manager: tagmanager.google.com
Google Search Console: search.google.com
Google Ads: ads.google.com
Google Marketing Platform: marketingplatform.google.com
Meta Business Suite: business.facebook.com
LinkedIn Campaign Manager: linkedin.com/campaignmanager
Microsoft Advertising: ads.microsoft.com
TikTok Ads: ads.tiktok.com
X Ads: ads.x.com
Reddit Ads: ads.reddit.com
Pinterest Ads: ads.pinterest.com
Snapchat Ads: ads.snapchat.com
Amazon Ads: advertising.amazon.com
The Trade Desk: thetradedesk.com
StackAdapt: stackadapt.com
AdRoll: adroll.com app.adroll.com
Criteo: criteo.com
Taboola: taboola.com
Outbrain: outbrain.com
Hotjar Surveys: hotjar.com/surveys
Typeform: typeform.com admin.typeform.com
SurveyMonkey: surveymonkey.com
Google Forms: forms.google.com
Microsoft Forms: forms.office.com forms.microsoft.com
Jotform: jotform.com
Tally: tally.so
Formstack: formstack.com
Cognito Forms: cognitoforms.com
Wufoo: wufoo.com
Paperform: paperform.co
Fillout: fillout.com
Qualtrics: qualtrics.com
Alchemer: alchemer.com app.alchemer.com
QuestionPro: questionpro.com
Delighted: delighted.com
Medallia: medallia.com
Qualaroo: qualaroo.com
Sprig: sprig.com app.sprig.com
Survicate: survicate.com
Unbounce Smart Builder: unbounce.com/smart-builder
Optimonk: optimonk.com
OptinMonster: optinmonster.com app.optinmonster.com
Sumo: sumo.com
Privy: privy.com dashboard.privy.com
Wisepops: wisepops.com app.wisepops.com
Hello Bar: hellobar.com
Bitly: bitly.com app.bitly.com
Rebrandly: rebrandly.com app.rebrandly.com
Dub: dub.co app.dub.co
Short.io: short.io app.short.io
Linktree: linktr.ee
Beacons: beacons.ai
Hootsuite Ads: hootsuite.com/ads
Canva Enterprise: canva.com/enterprise
Uberflip: uberflip.com
PathFactory: pathfactory.com
Demandbase: demandbase.com
6sense: 6sense.com
Bombora: bombora.com
Terminus: terminus.com
RollWorks: rollworks.com
Mutiny: mutinyhq.com app.mutinyhq.com
Clearbit: clearbit.com dashboard.clearbit.com
ZoomInfo: zoominfo.com app.zoominfo.com
Apollo: apollo.io app.apollo.io
Lusha: lusha.com dashboard.lusha.com
Cognism: cognism.com app.cognism.com
Seamless.AI: seamless.ai login.seamless.ai
RocketReach: rocketreach.co
Hunter: hunter.io
Clay: clay.com app.clay.com
Kaspr: kaspr.io app.kaspr.io
UpLead: uplead.com app.uplead.com
Dealfront: dealfront.com
Leadfeeder: leadfeeder.com app.leadfeeder.com
Albacross: albacross.com
Warmly: warmly.ai app.warmly.ai
RB2B: rb2b.com app.rb2b.com
G2: g2.com sell.g2.com
Capterra: capterra.com
TrustRadius: trustradius.com
Trustpilot: trustpilot.com businessapp.b2b.trustpilot.com
Yotpo: yotpo.com
Bazaarvoice: bazaarvoice.com
Birdeye: birdeye.com
Podium: podium.com app.podium.com
Reviews.io: reviews.io
Okendo: okendo.io
Stamped: stamped.io
Judge.me: judge.me
Gorgias: gorgias.com
Tidio: tidio.com
Drift: drift.com app.drift.com
Qualified: qualified.com app.qualified.com
LiveChat: livechat.com my.livechatinc.com
Olark: olark.com
tawk.to: tawk.to dashboard.tawk.to
Crisp: crisp.chat app.crisp.chat
Chatwoot: chatwoot.com app.chatwoot.com

## Sales and CRM
Salesforce: salesforce.com force.com lightning.force.com my.salesforce.com
Microsoft Dynamics 365: dynamics.com crm.dynamics.com
Zoho CRM: crm.zoho.com zoho.com
Pipedrive: pipedrive.com
Freshsales: freshworks.com myfreshworks.com
Close: close.com app.close.com
Copper: copper.com app.copper.com
Insightly: insightly.com
Nimble: nimble.com app.nimble.com
Capsule: capsulecrm.com
Streak: streak.com
Attio: attio.com app.attio.com
Folk: folk.app
Affinity: affinity.co
Keap: keap.com
Nutshell: nutshell.com app.nutshell.com
Less Annoying CRM: lessannoyingcrm.com
Agile CRM: agilecrm.com
SugarCRM: sugarcrm.com
Creatio: creatio.com
Monday Sales CRM: monday.com/crm
Outreach: outreach.io
Salesloft: salesloft.com app.salesloft.com
Groove: groove.co
Mixmax: mixmax.com app.mixmax.com
Yesware: yesware.com
Reply.io: reply.io run.reply.io
Lemlist: lemlist.com app.lemlist.com
Instantly: instantly.ai app.instantly.ai
Smartlead: smartlead.ai app.smartlead.ai
Woodpecker: woodpecker.co app.woodpecker.co
Mailshake: mailshake.com
Klenty: klenty.com
Gong: gong.io app.gong.io
Chorus: chorus.ai
Clari: clari.com app.clari.com
People.ai: people.ai
BoostUp: boostup.ai
Aviso: aviso.com
Highspot: highspot.com
Seismic: seismic.com
Showpad: showpad.com
Mediafly: mediafly.com
Allego: allego.com
Mindtickle: mindtickle.com
Lessonly: lessonly.com
Consensus: goconsensus.com
Walnut: walnut.io
Navattic: navattic.com app.navattic.com
Storylane: storylane.io app.storylane.io
Arcade: arcade.software app.arcade.software
Reprise: reprise.com
Demostack: demostack.com
Vidyard Sales: vidyard.com/sales
Sendoso: sendoso.com app.sendoso.com
Reachdesk: reachdesk.com
Postal: postal.com
LinkedIn Sales Navigator: linkedin.com/sales
LinkedIn: linkedin.com
Crossbeam: crossbeam.com app.crossbeam.com
Reveal: reveal.co app.reveal.co
PartnerStack: partnerstack.com app.partnerstack.com
Impartner: impartner.com
Allbound: allbound.com
Impact.com: impact.com app.impact.com
Rewardful: rewardful.com app.getrewardful.com
FirstPromoter: firstpromoter.com
CaptivateIQ: captivateiq.com app.captivateiq.com
Spiff: spiff.com
Xactly: xactlycorp.com
Varicent: varicent.com
QuotaPath: quotapath.com app.quotapath.com
DealHub: dealhub.io
Salesforce CPQ: salesforce.com/sales/cpq
Subskribe: subskribe.com
Ironclad CLM: ironcladapp.com/clm
RingCentral Contact Center: ringcentral.com/contact-center
Talkdesk: talkdesk.com mytalkdesk.com
Five9: five9.com
Genesys Cloud: genesys.com mypurecloud.com
NICE CXone: niceincontact.com nice.com
JustCall: justcall.io app.justcall.io
CloudTalk: cloudtalk.io my.cloudtalk.io
Orum: orum.com
Nooks: nooks.ai app.nooks.in
Kixie: kixie.com
Ringover: ringover.com dashboard.ringover.com
Zoom Contact Center: zoom.com/contact-center

## Customer support and success
Intercom: intercom.com app.intercom.com
Freshdesk: freshdesk.com
Help Scout: helpscout.com secure.helpscout.net
Kustomer: kustomer.com
Zoho Desk: desk.zoho.com
HappyFox: happyfox.com
Gladly: gladly.com
Dixa: dixa.com
Re:amaze: reamaze.com
Hiver: hiverhq.com
Groove HQ: groovehq.com
Kayako: kayako.com
LiveAgent: liveagent.com
Salesforce Service Cloud: salesforce.com/service
Forethought: forethought.ai
Ada: ada.cx
Decagon: decagon.ai
Sierra: sierra.ai
Ultimate: ultimate.ai
Yellow.ai: yellow.ai
Zowie: getzowie.com
Stonly: stonly.com
Gainsight: gainsight.com gainsightcloud.com
ChurnZero: churnzero.com app.churnzero.net
Totango: totango.com app.totango.com
Vitally: vitally.io
Planhat: planhat.com
ClientSuccess: clientsuccess.com
Catalyst: catalyst.io
Custify: custify.com
Staircase AI: staircase.ai
Appcues: appcues.com studio.appcues.com
WalkMe: walkme.com
Whatfix: whatfix.com
Userpilot: userpilot.com
Chameleon: chameleon.io app.chameleon.io
UserGuiding: userguiding.com
Userlane: userlane.com
Pendo Adopt: pendo.io/adopt
Beamer: getbeamer.com app.getbeamer.com
Headway: headwayapp.co
LaunchNotes: launchnotes.com
Frill: frill.co
Productlane: productlane.com
Nicereply: nicereply.com
Klaus: klausapp.com
MaestroQA: maestroqa.com
Playvox: playvox.com
Assembled: assembled.com app.assembled.com
Tymeshift: tymeshift.com
Calabrio: calabrio.com
Verint: verint.com
Loopio: loopio.com
RFPIO: rfpio.com
Responsive: responsive.io
Qvidian: qvidian.com

## HR and people
Workday: workday.com myworkday.com
BambooHR: bamboohr.com
Rippling: rippling.com app.rippling.com
Gusto: gusto.com app.gusto.com
ADP: adp.com workforcenow.adp.com
Paychex: paychex.com
Paylocity: paylocity.com
Paycom: paycomonline.net paycom.com
Paycor: paycor.com
UKG: ukg.com ultipro.com
Ceridian Dayforce: dayforce.com dayforcehcm.com
SAP SuccessFactors: successfactors.com sapsf.com
Oracle HCM: oraclecloud.com/hcm
Namely: namely.com
Justworks: justworks.com secure.justworks.com
TriNet: trinet.com
Insperity: insperity.com
Deel: deel.com app.deel.com
Remote: remote.com
Oyster: oysterhr.com app.oysterhr.com
Velocity Global: velocityglobal.com
Papaya Global: papayaglobal.com
Multiplier: usemultiplier.com
Globalization Partners: globalization-partners.com
Personio: personio.com
HiBob: hibob.com app.hibob.com
Factorial: factorialhr.com app.factorialhr.com
Sage HR: sage.hr
Zoho People: people.zoho.com
Humaans: humaans.io app.humaans.io
Charlie HR: charliehr.com
Breathe: breathehr.com
Leapsome: leapsome.com
Lattice: lattice.com
15Five: 15five.com
Culture Amp: cultureamp.com
Betterworks: betterworks.com
Small Improvements: small-improvements.com
Reflektive: reflektive.com
Workleap: workleap.com
Officevibe: officevibe.com
Peakon: peakon.com
Glint: glintinc.com
Qualtrics EmployeeXM: qualtrics.com/employee-experience
TINYpulse: tinypulse.com
Bonusly: bonus.ly
Kudos: kudos.com
Nectar: nectarhr.com
Assembly: joinassembly.com
Motivosity: motivosity.com
Awardco: award.co
Achievers: achievers.com
Workhuman: workhuman.com
Donut: donut.com
Sparkbay: sparkbay.com
ChartHop: charthop.com
Pingboard: pingboard.com
Organimi: organimi.com
Sift: justsift.com
Greenhouse: greenhouse.io app.greenhouse.io
Lever: lever.co hire.lever.co
Ashby: ashbyhq.com app.ashbyhq.com
Workable: workable.com
SmartRecruiters: smartrecruiters.com
iCIMS: icims.com
JazzHR: jazzhr.com app.jazz.co
Recruitee: recruitee.com
Teamtailor: teamtailor.com app.teamtailor.com
Breezy HR: breezy.hr app.breezy.hr
Jobvite: jobvite.com
Bullhorn: bullhorn.com
Gem: gem.com
Beamery: beamery.com
Phenom: phenom.com
Paradox: paradox.ai
HireVue: hirevue.com
Codility: codility.com app.codility.com
HackerRank: hackerrank.com
CodeSignal: codesignal.com app.codesignal.com
CoderPad: coderpad.io app.coderpad.io
Karat: karat.com
TestGorilla: testgorilla.com app.testgorilla.com
Criteria: criteriacorp.com
Checkr: checkr.com dashboard.checkr.com
Sterling: sterlingcheck.com
HireRight: hireright.com
GoodHire: goodhire.com
Certn: certn.co
Indeed for Employers: employers.indeed.com
Handshake: joinhandshake.com app.joinhandshake.com
Upwork: upwork.com
Fiverr: fiverr.com
Toptal: toptal.com
Contra: contra.com
Worksome: worksome.com
LinkedIn Recruiter: linkedin.com/talent
LinkedIn Learning: linkedin.com/learning
Coursera: coursera.org
Udemy: udemy.com
Udemy Business: business.udemy.com
Pluralsight: pluralsight.com app.pluralsight.com
Skillsoft Percipio: percipio.com
edX: edx.org
Degreed: degreed.com
Docebo: docebo.com
TalentLMS: talentlms.com
Absorb LMS: absorblms.com
LearnUpon: learnupon.com
Lessonly by Seismic: seismic.com/lessonly
360Learning: 360learning.com
Thinkific: thinkific.com
Teachable: teachable.com
Kajabi: kajabi.com app.kajabi.com
Podia: podia.com app.podia.com
Rise: rise.com articulate.com
Articulate 360: articulate.com id.articulate.com
iSpring: ispringsolutions.com ispringlearn.com
Cornerstone: cornerstoneondemand.com csod.com
Sana: sanalabs.com
Go1: go1.com
O'Reilly Learning: oreilly.com learning.oreilly.com
DataCamp: datacamp.com app.datacamp.com
Codecademy: codecademy.com
Benefitfocus: benefitfocus.com
Justworks Benefits: justworks.com/benefits
Guideline: guideline.com
Human Interest: humaninterest.com
Carta: carta.com app.carta.com
Pulley: pulley.com
Ledgy: ledgy.com app.ledgy.com
Shareworks: shareworks.com
Pave: pave.com app.pave.com
Compa: trycompa.com
Carta Total Comp: carta.com/total-compensation
Payscale: payscale.com
Figures: figures.hr app.figures.hr
Deputy: deputy.com
When I Work: wheniwork.com
Homebase: joinhomebase.com app.joinhomebase.com
7shifts: 7shifts.com app.7shifts.com
Connecteam: connecteam.com app.connecteam.com
Sling: getsling.com app.getsling.com
Humanity: humanity.com
Shiftbase: shiftbase.com
Workyard: workyard.com
QuickBooks Time: tsheets.com quickbooks.intuit.com/time-tracking
Expensify: expensify.com
Navan: navan.com app.navan.com
TravelPerk: travelperk.com app.travelperk.com
Egencia: egencia.com
SAP Concur: concursolutions.com concur.com
Emburse: emburse.com
Certify: certify.com
Rydoo: rydoo.com app.rydoo.com
Pleo: pleo.io app.pleo.io
Spendesk: spendesk.com app.spendesk.com
Payhawk: payhawk.com
Soldo: soldo.com
Airbase: airbase.com dashboard.airbase.io
Ramp: ramp.com app.ramp.com
Brex: brex.com dashboard.brex.com
Mercury: mercury.com app.mercury.com
Divvy: getdivvy.com app.divvy.co
BILL: bill.com app.bill.com
Tipalti: tipalti.com
AvidXchange: avidxchange.com
Coupa: coupa.com coupahost.com
Procurify: procurify.com
Zip: ziphq.com
Precoro: precoro.com
Order.co: order.co
Amazon Business: business.amazon.com

## Finance and accounting
QuickBooks Online: qbo.intuit.com quickbooks.intuit.com intuit.com
Xero: xero.com go.xero.com
NetSuite: netsuite.com app.netsuite.com
Sage Intacct: sageintacct.com intacct.com
FreshBooks: freshbooks.com my.freshbooks.com
Wave: waveapps.com
Zoho Books: books.zoho.com
Zoho Invoice: invoice.zoho.com
Zoho Expense: expense.zoho.com
Microsoft Dynamics 365 Business Central: businesscentral.dynamics.com
SAP S/4HANA Cloud: s4hana.cloud.sap
Oracle Fusion Cloud ERP: fa.us2.oraclecloud.com
Acumatica: acumatica.com
Odoo: odoo.com
Epicor: epicor.com
Infor: infor.com
Workday Financials: workday.com/financial-management
Campfire: campfire.ai
Rillet: rillet.com
Puzzle: puzzle.io
Digits: digits.com
Pilot: pilot.com app.pilot.com
Bench: bench.co
Botkeeper: botkeeper.com
FloQast: floqast.com
BlackLine: blackline.com
Numeric: numeric.io app.numeric.io
Trintech: trintech.com
Vena: venasolutions.com
Adaptive Planning: adaptiveinsights.com
Anaplan: anaplan.com
Pigment: pigment.com
Mosaic: mosaic.tech app.mosaic.tech
Cube: cubesoftware.com
Causal: causal.app
Jirav: jirav.com
Planful: planful.com
Datarails: datarails.com
Abacum: abacum.io app.abacum.io
Runway Financial: runway.com app.runway.com
Fathom HQ: fathomhq.com app.fathomhq.com
Stripe: stripe.com dashboard.stripe.com
PayPal: paypal.com
Braintree: braintreepayments.com braintreegateway.com
Adyen: adyen.com ca-live.adyen.com
Square: squareup.com squareupsandbox.com
Checkout.com: checkout.com dashboard.checkout.com
Paddle: paddle.com vendors.paddle.com
Chargebee: chargebee.com
Recurly: recurly.com app.recurly.com
Chargify: chargify.com
Maxio: maxio.com
Zuora: zuora.com
Recharge: rechargepayments.com admin.rechargeapps.com
Lago: getlago.com app.getlago.com
Orb: withorb.com app.withorb.com
Metronome: metronome.com app.metronome.com
Stripe Billing: stripe.com/billing
Invoiced: invoiced.com
Tesorio: tesorio.com
Upflow: upflow.io app.upflow.io
Chaser: chaserhq.com app.chaserhq.com
HighRadius: highradius.com
Versapay: versapay.com
Avalara: avalara.com admin.avalara.com
TaxJar: taxjar.com app.taxjar.com
Anrok: anrok.com app.anrok.com
Vertex: vertexinc.com
Sovos: sovos.com
Quaderno: quaderno.io
Wise: wise.com
Payoneer: payoneer.com
Airwallex: airwallex.com www.airwallex.com
Revolut Business: business.revolut.com revolut.com
Rho: rho.co
Relay: relayfi.com app.relayfi.com
Novo: novo.co
Silicon Valley Bank: svb.com
JPMorgan Access: access.jpmorgan.com
HSBCnet: hsbcnet.com
Plaid: plaid.com dashboard.plaid.com
Modern Treasury: moderntreasury.com app.moderntreasury.com
Kyriba: kyriba.com
Trovata: trovata.io app.trovata.io
Bloomberg: bloomberg.com
PitchBook: pitchbook.com my.pitchbook.com
Crunchbase: crunchbase.com
CB Insights: cbinsights.com app.cbinsights.com
AlphaSense: alpha-sense.com research.alpha-sense.com
Tegus: tegus.com
Koyfin: koyfin.com app.koyfin.com
FactSet: factset.com
S&P Capital IQ: capitaliq.com
Refinitiv: refinitiv.com
Morningstar: morningstar.com
Visible: visible.vc
AngelList: angellist.com venture.angellist.com
Juniper Square: junipersquare.com
Allvue: allvuesystems.com
DealCloud: dealcloud.com
Affinity for VC: affinity.co/vc
Fireblocks: fireblocks.com console.fireblocks.io
BitGo: bitgo.com app.bitgo.com

## Analytics and data
Tableau: tableau.com online.tableau.com
Microsoft Power BI: powerbi.com app.powerbi.com
Looker: looker.com cloud.looker.com
Looker Studio: lookerstudio.google.com datastudio.google.com
Metabase Cloud: metabase.com metabaseapp.com
Mode: mode.com app.mode.com
Sigma: sigmacomputing.com app.sigmacomputing.com
Hex: hex.tech app.hex.tech
Deepnote: deepnote.com
Observable: observablehq.com
Streamlit Cloud: streamlit.io share.streamlit.io
Qlik Cloud: qlik.com qlikcloud.com
Domo: domo.com
ThoughtSpot: thoughtspot.com thoughtspot.cloud
Sisense: sisense.com
Zoho Analytics: analytics.zoho.com
Klipfolio: klipfolio.com app.klipfolio.com
Databox: databox.com app.databox.com
Geckoboard: geckoboard.com app.geckoboard.com
Grow: grow.com
Holistics: holistics.io
Preset: preset.io manage.app.preset.io
Lightdash: lightdash.com app.lightdash.cloud
Omni: omni.co
Evidence: evidence.dev
Count: count.co
Equals: equals.com
Rows: rows.com
Snowflake: snowflakecomputing.com app.snowflake.com snowflake.com
Databricks: databricks.com cloud.databricks.com azuredatabricks.net
Google BigQuery: console.cloud.google.com/bigquery
Firebolt: firebolt.io go.firebolt.io
MotherDuck: motherduck.com app.motherduck.com
Starburst Galaxy: starburst.io galaxy.starburst.io
Dremio Cloud: dremio.com app.dremio.cloud
dbt Cloud: getdbt.com cloud.getdbt.com
Fivetran: fivetran.com
Airbyte Cloud: airbyte.com cloud.airbyte.com
Stitch: stitchdata.com app.stitchdata.com
Hevo: hevodata.com
Matillion: matillion.com
Census: getcensus.com app.getcensus.com
Hightouch: hightouch.com app.hightouch.com
Polytomic: polytomic.com app.polytomic.com
Estuary: estuary.dev dashboard.estuary.dev
Meltano Cloud: meltano.com
Astronomer: astronomer.io cloud.astronomer.io
Prefect Cloud: prefect.io app.prefect.cloud
Dagster Cloud: dagster.io dagster.cloud
Monte Carlo: montecarlodata.com getmontecarlo.com
Bigeye: bigeye.com app.bigeye.com
Anomalo: anomalo.com
Soda: soda.io cloud.soda.io
Atlan: atlan.com
Alation: alation.com
Collibra: collibra.com
Secoda: secoda.co app.secoda.co
Select Star: selectstar.com
data.world: data.world
Confluent Cloud: confluent.io confluent.cloud
Redpanda Cloud: redpanda.com cloud.redpanda.com
Aiven for Kafka: aiven.io/kafka
Tinybird: tinybird.co ui.tinybird.co
Rockset: rockset.com
Materialize: materialize.com console.materialize.com
Google Sheets: sheets.google.com
Microsoft Excel Online: excel.cloud.microsoft
Smartsheet Dynamic View: smartsheet.com/dynamic-view
Grist: getgrist.com
Baserow: baserow.io
NocoDB Cloud: nocodb.com app.nocodb.com
SeaTable: seatable.io
Stacker: stackerhq.com
Julius AI: julius.ai
Akkio: akkio.com

## Storage, backup and email security
Backblaze: backblaze.com secure.backblaze.com
Wasabi: wasabi.com console.wasabisys.com
Carbonite: carbonite.com
Acronis: acronis.com cloud.acronis.com
Veeam: veeam.com
Druva: druva.com
Datto Backup: datto.com/products/backup
Spanning: spanning.com
Backupify: backupify.com
OwnBackup: ownbackup.com
Rewind: rewind.com app.rewind.com
Keepit: keepit.com
AvePoint: avepoint.com
SkyKick: skykick.com
CloudAlly: cloudally.com
IDrive: idrive.com
Arq: arqbackup.com
Crashplan: crashplan.com

## E-commerce and operations
Shopify: shopify.com myshopify.com admin.shopify.com
BigCommerce: bigcommerce.com login.bigcommerce.com
WooCommerce: woocommerce.com
Magento: magento.com
commercetools: commercetools.com mc.commercetools.com
Ecwid: ecwid.com my.ecwid.com
Gumroad: gumroad.com app.gumroad.com
Lemon Squeezy: lemonsqueezy.com app.lemonsqueezy.com
ShipStation: shipstation.com ship.shipstation.com
ShipBob: shipbob.com web.shipbob.com
Shippo: goshippo.com apps.goshippo.com
EasyPost: easypost.com
Flexport: flexport.com app.flexport.com
Freightos: freightos.com
project44: project44.com
FourKites: fourkites.com
Samsara: samsara.com cloud.samsara.com
Motive: gomotive.com app.gomotive.com
Fleetio: fleetio.com secure.fleetio.com
Onfleet: onfleet.com
Routific: routific.com
Linnworks: linnworks.com
Cin7: cin7.com
Katana: katanamrp.com
Fishbowl: fishbowlinventory.com
inFlow: inflowinventory.com
Sortly: sortly.com app.sortly.com
Skubana: skubana.com
Extensiv: extensiv.com
Sellbrite: sellbrite.com
ChannelAdvisor: channeladvisor.com
Feedonomics: feedonomics.com
Amazon Seller Central: sellercentral.amazon.com
Faire: faire.com
Toast: toasttab.com pos.toasttab.com
Lightspeed: lightspeedhq.com
Clover: clover.com
Revel Systems: revelsystems.com
Procore: procore.com app.procore.com
Autodesk Construction Cloud: construction.autodesk.com acc.autodesk.com
Autodesk: autodesk.com accounts.autodesk.com
Buildertrend: buildertrend.com
Fieldwire: fieldwire.com app.fieldwire.com
PlanGrid: plangrid.com
ServiceTitan: servicetitan.com go.servicetitan.com
Jobber: getjobber.com secure.getjobber.com
Housecall Pro: housecallpro.com pro.housecallpro.com
FieldEdge: fieldedge.com
ServiceMax: servicemax.com
Salesforce Field Service: salesforce.com/service/field-service
SafetyCulture: safetyculture.com app.safetyculture.com
Fulcrum: fulcrumapp.com web.fulcrumapp.com
Tulip: tulip.co
Veeva Vault: veevavault.com veeva.com
Benchling: benchling.com
LabArchives: labarchives.com
athenahealth: athenahealth.com
Elation Health: elationhealth.com
Healthie: gethealthie.com
SimplePractice: simplepractice.com secure.simplepractice.com
Doxy.me: doxy.me
Canvas Medical: canvasmedical.com
Yardi: yardi.com
AppFolio: appfolio.com
Buildium: buildium.com
Entrata: entrata.com
RealPage: realpage.com
Zillow Premier Agent: premieragent.zillow.com
Follow Up Boss: followupboss.com app.followupboss.com
kvCORE: kvcore.com
Dotloop: dotloop.com
SkySlope: skyslope.com

## Education
Google Classroom: classroom.google.com
Canvas LMS: instructure.com canvas.instructure.com
Blackboard: blackboard.com
Moodle Cloud: moodlecloud.com
Schoology: schoology.com app.schoology.com
Brightspace: d2l.com
Clever: clever.com
ClassDojo: classdojo.com
Seesaw: seesaw.me app.seesaw.me
Nearpod: nearpod.com
Pear Deck: peardeck.com
Edpuzzle: edpuzzle.com
Quizlet: quizlet.com
Quizizz: quizizz.com wayground.com
Gradescope: gradescope.com
Turnitin: turnitin.com
Chegg: chegg.com
Khan Academy: khanacademy.org
Remind: remind.com
PowerSchool: powerschool.com
Infinite Campus: infinitecampus.com
Securly: securly.com
GoGuardian: goguardian.com
Lightspeed Systems: lightspeedsystems.com

## Messaging and community
Stack Overflow: stackoverflow.com
Product Hunt: producthunt.com
Vimeo OTT: vhx.tv
Circle: circle.so app.circle.so
Discourse: discourse.org
Bettermode: bettermode.com
Mighty Networks: mightynetworks.com
Skool: skool.com
Khoros: khoros.com
Higher Logic: higherlogic.com
Common Room: commonroom.io app.commonroom.io
Orbit: orbit.love
Telegram Web: web.telegram.org
WhatsApp Web: web.whatsapp.com
Signal: signal.org
Messenger: messenger.com
LINE: line.me
WeChat Web: wx.qq.com web.wechat.com
Viber: viber.com
Skype: skype.com web.skype.com

## Events and business travel
TripActions: tripactions.com
Spotnana: spotnana.com
Uber for Business: business.uber.com
Eventbrite: eventbrite.com
Cvent: cvent.com app.cvent.com
Bizzabo: bizzabo.com
Splash: splashthat.com
Hubilo: hubilo.com
Swapcard: swapcard.com
Goldcast: goldcast.io
ON24: on24.com
Zoom Events: events.zoom.us
Luma: lu.ma luma.com
Sessionize: sessionize.com
Brella: brella.io
Whova: whova.com
EventMobi: eventmobi.com
Social Tables: socialtables.com
`;
