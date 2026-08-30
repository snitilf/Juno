use framework "Foundation"

on run arguments
    if (count of arguments) is not 5 then error "expected process, result, start marker, end marker, and timeout"
    set processName to item 1 of arguments
    set resultPath to item 2 of arguments
    set startMarker to item 3 of arguments
    set endMarker to item 4 of arguments
    set timeoutSeconds to (item 5 of arguments) as integer
    tell application "System Events"
        if not (exists process processName) then error "desktop process is not running"
        tell process processName
            set frontmost to true
            keystroke "n" using command down
            my pauseFor(2)
            keystroke "v" using command down
            key code 36
        end tell
    end tell
    set deadline to current application's NSDate's dateWithTimeIntervalSinceNow:timeoutSeconds
    repeat
        if (deadline's timeIntervalSinceNow() as real) is less than or equal to 0 then error "desktop result capture timed out"
        my pauseFor(2)
        set visibleText to my readVisibleText(processName)
        set resultText to my extractLastResult(visibleText, startMarker, endMarker)
        if resultText is not missing value then
            my writeResult(resultPath, resultText)
            return
        end if
    end repeat
end run

on pauseFor(secondsToWait)
    current application's NSThread's sleepForTimeInterval:secondsToWait
end pauseFor

on readVisibleText(processName)
    set output to ""
    tell application "System Events"
        tell process processName
            if not (exists front window) then error "desktop window is missing"
            set elements to entire contents of front window
            repeat with elementRef in elements
                try
                    set itemValue to value of elementRef as text
                    if itemValue is not "" then set output to output & linefeed & itemValue
                end try
                try
                    set itemTitle to title of elementRef as text
                    if itemTitle is not "" then set output to output & linefeed & itemTitle
                end try
                try
                    set itemDescription to description of elementRef as text
                    if itemDescription is not "" then set output to output & linefeed & itemDescription
                end try
            end repeat
        end tell
    end tell
    return output
end readVisibleText

on extractLastResult(sourceText, startMarker, endMarker)
    set savedDelimiters to AppleScript's text item delimiters
    try
        set AppleScript's text item delimiters to startMarker
        set startParts to text items of sourceText
        if (count of startParts) < 2 then
            set AppleScript's text item delimiters to savedDelimiters
            return missing value
        end if
        set tailText to item -1 of startParts
        set AppleScript's text item delimiters to endMarker
        set endParts to text items of tailText
        if (count of endParts) < 2 then
            set AppleScript's text item delimiters to savedDelimiters
            return missing value
        end if
        set resultText to item 1 of endParts
        set AppleScript's text item delimiters to savedDelimiters
        return resultText
    on error
        set AppleScript's text item delimiters to savedDelimiters
        return missing value
    end try
end extractLastResult

on writeResult(resultPath, resultText)
    set resultString to current application's NSString's stringWithString:resultText
    set writeError to reference
    set didWrite to resultString's writeToFile:resultPath atomically:true encoding:(current application's NSUTF8StringEncoding) |error|:writeError
    if didWrite is false then error "could not write desktop result"
end writeResult
