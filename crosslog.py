"""Class file used to define the cross log pipeline.
"""
from parsers.auto_detect import get_parser_for_file
from config import CrossLogPipelineConfig
from models.run_result import RunResult
from models.parsed_event import ParsedEvent, ParserErrorEvent
from normalizer.normalize import normalize_event
from detection.engine import detect

class CrossLogPipeline:
    """Main CrossLog Pipeline object facade pattern
    """
    def __init__(self,config:CrossLogPipelineConfig):
        self.config = config
    
    def run(self, files):
        """Primary method to used to start the processing of ingested log files.

        Args:
            files (List[Path]): Ingest files selected by the user.

        Returns:
            RunResult: Results from the processing all the user files.
        """
        result = RunResult()
         
        # Main loop to check every log file discovered       
        for file_path in files:
            # Process each file from the list.
            self._process_file(file_path=file_path,result=result)
        
            # Terminate the application if the user selected fast break
            if self.config.fail_fast and result.fatal_errors > 0:
                break
            
        return result
    
    def _process_file(self, file_path, result):
        """Private method used to process a single file.

        Args:
            file_path (Path): File path object to the input file.
            result (RunResult): Results for this run. Pass-by reference. 
        """
        try:
            # Determine the parser from the input or by the user.
            parser = get_parser_for_file(
                file_path=file_path,
                forced_format=self.config.input_format) 
            
        except Exception as exc:
            # Logs the file error if the method fails to select the parser.
            result.add_file_error(
                source=str(file_path),
                stage="parser_selection",
                error=str(exc),
            )
            result.fatal_errors += 1
            return
        
        # Increment the number of files processed.
        result.files_processed += 1
        
        # Parser will loop thru the file and extract findings.
        for parser_event in parser.parse_file(file_path):
            # If this is a ParserErrorEvent add it to the list of errors
            if isinstance(parser_event, ParserErrorEvent):
                result.add_parser_error(
                    source=str(file_path),
                    event=parser_event,
                )
                
                # No reason to keep going; this event is done.
                continue
            
            try:
                # Normalize the parser event message.
                event = normalize_event(parser_event)
                # Add the normalized event to the list.
                result.normalized_events.append(event)
            except Exception as exc:
                result.add_normalization_error(
                    source=str(file_path),
                    stage="normalize",
                    error=str(exc),
                    event=parser_event,
                )
                
                # Break out if the fail_fast is set.
                if self.config.fail_fast:
                    result.fatal_errors += 1
                    return
                # No reason to keep going; this event is done.
                continue
            
            try:
                # Attempt to detect findings from the normalized event.
                finding = detect(event)
                # If not None, then add it to the results findings.
                if finding:
                    result.findings.extend(finding)
            except Exception as exc:
                result.add_detection_error(
                    source=str(file_path),
                    stage="detect",
                    error=str(exc),
                    event=event,
                )
                
                # Break out if the fail_fast is set.                
                if self.config.fail_fast:
                    result.fatal_errors += 1
                    return
                
            
            
        