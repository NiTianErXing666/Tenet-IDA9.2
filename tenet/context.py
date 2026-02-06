import os
import logging
import traceback
import threading

from tenet.util.qt import *
from tenet.util.log import pmsg
from tenet.util.misc import is_plugin_dev

from tenet.stack import StackController
from tenet.memory import MemoryController
from tenet.registers import RegisterController
from tenet.breakpoints import BreakpointController
from tenet.ui.trace_view import TraceDock

from tenet.types import BreakpointType
from tenet.trace.arch import ArchAMD64, ArchX86, ArchAArch64 # Added ArchAArch64
from tenet.trace.reader import TraceReader
from tenet.integration.api import disassembler, DisassemblerContextAPI

logger = logging.getLogger("Tenet.Context")

#------------------------------------------------------------------------------
# context.py -- Plugin Database Context
#------------------------------------------------------------------------------
#
#    The purpose of this file is to house and manage the plugin's
#    disassembler database (eg, IDB/BNDB) specific runtime state.
#
#    At a high level, a unique 'instance' of the plugin runtime & subsystems
#    are initialized for each opened database in supported disassemblers. The
#    plugin context object acts a bit like the database specific plugin core.
# 
#    For example, it is possible for multiple databases to be open at once
#    in the Binary Ninja disassembler. Each opened database will have a
#    unique plugin context object created and used to manage state, UI,
#    threads/subsystems, and loaded plugin data for that database.
#
#    In IDA, this is less important as you can only have one database open
#    at any given time (... at least at the time of writing) but that does
#    not change how this context system works under the hood.
#

class TenetContext(object):
    """
    A per-database encapsulation of the plugin components / state.
    """

    def __init__(self, core, db):
        disassembler[self] = DisassemblerContextAPI(db)
        self.core = core
        self.db = db

        # select a trace arch based on the binary the disassmbler has loaded
        # NOTE: We assume the existence of an is_aarch64() method in the disassembler API.
        # This might need to be implemented in the integration layer later.
        # Determine architecture class using the new method in the integration API
        ArchClass = disassembler[self].get_tenet_arch_class()
        self.arch = ArchClass()
        logger.info(f"Selected Architecture: {ArchClass.__name__}")

        # this will hold the trace reader when a trace has been loaded
        self.reader = None

        # plugin widgets / components
        self.breakpoints = BreakpointController(self)
        self.trace = TraceDock(self)  # TODO: port this one to MVC pattern
        self.stack = StackController(self)
        self.memory = MemoryController(self)
        self.registers = RegisterController(self)

        # the directory to start the 'load trace file' dialog in
        self._last_directory = None
        
        # whether the plugin subsystems have been created / started
        self._started = False

        # NOTE/DEV: automatically open a test trace file when dev/testing
        if is_plugin_dev():
            self._auto_launch()

    def _auto_launch(self):
        """
        Automatically load a static trace file when the database has been opened.
        
        NOTE/DEV: this is just to make it easier to test / develop / debug the
        plugin when developing it and should not be called under normal use.
        """

        def test_load():
            import ida_loader
            trace_filepath = ida_loader.get_plugin_options("Tenet")
            focus_window()
            self.load_trace(trace_filepath)
            self.show_ui()

        def dev_launch():
            self._timer = QtCore.QTimer()
            self._timer.singleShot(500, test_load) # delay to let things settle

        self.core._ui_hooks.ready_to_run = dev_launch

    #-------------------------------------------------------------------------
    # Properties
    #-------------------------------------------------------------------------

    @property
    def palette(self):
        return self.core.palette
    
    #-------------------------------------------------------------------------
    # Setup / Teardown
    #-------------------------------------------------------------------------

    def start(self):
        """
        One-time initialization of the plugin subsystems.

        This will only be called when it is clear the user is attempting
        to use the plugin or its functionality (eg, they click load trace).
        """
        if self._started:
            return

        self.palette.warmup()
        self._started = True

    def terminate(self):
        """
        Spin down any plugin subsystems as the context is being deleted.

        This will be called when the database or disassembler is closing.
        """
        self.close_trace()
    
    #-------------------------------------------------------------------------
    # Public API
    #-------------------------------------------------------------------------

    def trace_loaded(self):
        """
        Return True if a trace is loaded / active in this plugin context.
        """
        return bool(self.reader)

    def load_trace(self, filepath):
        """
        Load a trace from the given filepath.

        If there is a trace already loaded / in-use prior to calling this
        function, it will simply be replaced by the new trace.
        """

        #
        # create the trace reader. this will load the given trace file from
        # disk and wrap it with a number of useful APIs for navigating the
        # trace and querying information (memory, registers) from it at
        # chosen states of execution
        #

        self.reader = TraceReader(filepath, self.arch, disassembler[self])
        pmsg(f"Loaded trace {self.reader.trace.filepath}")
        pmsg(f"- {self.reader.trace.length:,} instructions...")

        #gmg commented the following check points
        # if self.reader.analysis.slide != None:
        #     pmsg(f"- {self.reader.analysis.slide:08X} ASLR slide...")
        # else:
        #     disassembler.warning("Failed to automatically detect ASLR base!\n\nSee console for more info...")
        #     pmsg(" +------------------------------------------------------")
        #     pmsg(" |- ERROR: Failed to detect ASLR base for this trace.")
        #     pmsg(" |       ---------------------------------------     ")
        #     pmsg(" +-+  You can 'try' rebasing the database to the correct ASLR base")
        #     pmsg("   |  if you know it, and reload the trace. Otherwise, it is possible")
        #     pmsg("   |  your trace is just... very small and Tenet was not confident")
        #     pmsg("   |  predicting an ASLR slide.")

        #
        # we only hook directly into the disassembler / UI / subsytems once
        # a trace is loaded. this ensures that our python handlers don't
        # introduce overhead on misc disassembler callbacks when the plugin
        # isn't even being used in the reversing session.
        #

        self.core.hook()

        #
        # attach the trace engine to the various plugin UI controllers, giving
        # them the necessary access to drive the underlying trace reader
        #

        self.breakpoints.reset()
        self.trace.attach_reader(self.reader)
        self.stack.attach_reader(self.reader)
        self.memory.attach_reader(self.reader)
        self.registers.attach_reader(self.reader)

        #
        # connect any high level signals from the new trace reader
        #

        self.reader.idx_changed(self._idx_changed)

    def close_trace(self):
        """
        Close the current trace if one is active.
        """
        if not self.reader:
            return

        #
        # unhook the disassembler, as there will be no active / loaded trace
        # after this routine completes
        #

        self.core.unhook()

        #
        # close UI elements and reset their model / controllers
        #

        self.trace.hide()
        self.trace.detach_reader()
        self.stack.hide()
        self.stack.detach_reader()
        self.memory.hide()
        self.memory.detach_reader()
        self.registers.hide()
        self.registers.detach_reader()

        # misc / final cleanup
        self.breakpoints.reset()
        #self.reader.close()

        self.reader = None

    def show_ui(self):
        """
        Integrate and arrange the plugin widgets into the disassembler UI.

        TODO: ehh, there really shouldn't be any disassembler-specific stuff
        outside of the disassembler integration files. it doesn't really
        matter much right now but this should be moved in the future.
        """
        import ida_kernwin
        self.registers.show(position=ida_kernwin.DP_RIGHT)

        #self.breakpoints.dockable.set_dock_position("CPU Registers", ida_kernwin.DP_BOTTOM)
        #self.breakpoints.dockable.show()

        #ida_kernwin.activate_widget(ida_kernwin.find_widget("Output window"), True)
        #ida_kernwin.set_dock_pos("Output window", None, ida_kernwin.DP_BOTTOM)
        #ida_kernwin.set_dock_pos("IPython Console", "Output", ida_kernwin.DP_INSIDE)

        #self.memory.dockable.set_dock_position("Output window", ida_kernwin.DP_TAB | ida_kernwin.DP_BEFORE)
        self.memory.show("Output window", ida_kernwin.DP_TAB | ida_kernwin.DP_BEFORE)

        #self.stack.dockable.set_dock_position("Memory View", ida_kernwin.DP_RIGHT)
        self.stack.show("Memory View", ida_kernwin.DP_RIGHT)

        mw = get_qmainwindow()
        mw.addToolBar(QtCore.Qt.RightToolBarArea, self.trace)
        self.trace.show()

        # trigger update check
        self.core.check_for_update()
    
    #-------------------------------------------------------------------------
    # Integrated UI Event Handlers
    #-------------------------------------------------------------------------

    def interactive_load_trace(self, reloading=False):
        """
        Handle UI actions for loading a trace file asynchronously.
        """
        # prompt the user with a file dialog to select a trace of interest
        filenames = self._select_trace_file()
        if not filenames:
            return

        # TODO: ehh, only support loading one trace at a time right now
        assert len(filenames) == 1, "Please select only one trace file to load"

        filepath = filenames[0]

        # Initialize loading state
        self._loading_cancelled = False
        self._load_complete = False
        self._load_error = None
        self._load_result = None
        self._is_reloading = reloading

        # Create progress wait box with cancel support
        from tenet.util.qt.waitbox import WaitBox
        self._load_wait_box = WaitBox(
            f"Loading trace...\n{os.path.basename(filepath)}\n\nInitializing...",
            "Loading Trace - Please Wait",
            abort=self._abort_load_trace
        )
        self._load_wait_box.show(modal=False)

        # Define progress callback for the loader
        def progress_callback(percent, message):
            """Progress callback during trace loading"""
            if self._loading_cancelled:
                return

            # Update wait box text
            self._load_wait_box.set_text(
                f"Loading trace...\n{os.path.basename(filepath)}\n\n{message}\n{percent}%"
            )

            # Process UI events to keep IDA responsive
            qta = QtCore.QCoreApplication.instance()
            if qta:
                qta.processEvents()

        # Start background thread for loading
        self._load_thread = threading.Thread(
            target=self._load_trace_async,
            args=(filepath, progress_callback),
            daemon=True
        )
        self._load_thread.start()

        # Setup timer to check completion
        self._load_timer = QtCore.QTimer()
        self._load_timer.timeout.connect(self._check_load_complete)
        self._load_timer.start(100)  # Check every 100ms

    def _abort_load_trace(self):
        """Cancel the ongoing trace loading"""
        self._loading_cancelled = True
        pmsg("Trace loading cancelled by user")

    def _load_trace_async(self, filepath, progress_callback):
        """
        Load trace in background thread (TraceFile only, no IDA API calls)
        """
        try:
            if self._loading_cancelled:
                logger.info("Loading was cancelled before starting")
                return

            # Import here to avoid circular dependency
            from tenet.trace.file import TraceFile

            # Only load TraceFile in background thread (pure file I/O, no IDA API)
            # This avoids the "Function can be called from the main thread only" error
            trace_file = TraceFile(filepath, self.arch, progress_callback=progress_callback)

            # Store the loaded trace file for main thread to create TraceReader
            self._loaded_trace_file = trace_file
            self._load_result = "trace_file_loaded"
            logger.info(f"Successfully loaded trace file with {trace_file.length:,} instructions")

        except Exception as e:
            error_msg = str(e)
            import traceback as tb
            error_msg += "\n" + tb.format_exc()
            self._load_error = error_msg
            logger.error(f"Failed to load trace file: {error_msg}")

    def _check_load_complete(self):
        """
        Check if background loading is complete and finalize in main thread
        """
        # Check if thread is still running
        if self._load_thread.is_alive():
            # Still loading, continue checking
            return

        # Loading complete or failed
        self._load_timer.stop()
        self._load_wait_box.close()

        # Handle cancellation
        if self._loading_cancelled:
            pmsg("Trace loading was cancelled")
            return

        # Handle errors
        if self._load_error:
            pmsg("Failed to load trace...")
            pmsg(self._load_error)
            # Show error dialog
            import ida_kernwin
            ida_kernwin.warning(f"Failed to load trace:\n{self._load_error[:500]}")
            return

        # Handle success - create TraceReader in main thread
        if self._load_result == "trace_file_loaded":
            try:
                # Show final progress update
                self._load_wait_box.set_text(
                    f"Finalizing trace...\n{os.path.basename(self._loaded_trace_file.filepath)}\n\nInitializing reader..."
                )
                qta = QtCore.QCoreApplication.instance()
                if qta:
                    qta.processEvents()

                # Create TraceReader in main thread with pre-loaded TraceFile
                # (can safely call IDA APIs now because we're in main thread)
                self.reader = TraceReader(
                    None,  # filepath not needed
                    self.arch,
                    disassembler[self],
                    trace_file=self._loaded_trace_file  # Use pre-loaded TraceFile
                )

                pmsg(f"Loaded trace {self.reader.trace.filepath}")
                pmsg(f"- {self.reader.trace.length:,} instructions...")

                # Finalize in main thread (UI operations must be in main thread)
                self._finalize_load_after_async()

            except Exception as e:
                pmsg("Failed to finalize trace loading...")
                pmsg(traceback.format_exc())
                import ida_kernwin
                ida_kernwin.warning(f"Failed to initialize trace reader:\n{str(e)[:500]}")

    def _finalize_load_after_async(self):
        """
        Finalize loading after async thread completes (runs in main thread)
        """
        # Hook into disassembler
        self.core.hook()

        # Attach trace engine to UI controllers
        self.breakpoints.reset()
        self.trace.attach_reader(self.reader)
        self.stack.attach_reader(self.reader)
        self.memory.attach_reader(self.reader)
        self.registers.attach_reader(self.reader)

        # Connect trace reader signals
        self.reader.idx_changed(self._idx_changed)

        # Show UI if not reloading
        if not self._is_reloading:
            self.show_ui()
        
    def interactive_next_execution(self):
        """
        Handle UI actions for seeking to the next execution of the selected address.
        """
        address = disassembler[self].get_current_address()
        rebased_address = self.reader.analysis.rebase_pointer(address)
        result = self.reader.seek_to_next(rebased_address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            pmsg(f"Go to 0x{address:08x} failed, no future executions of address")

    def interactive_prev_execution(self):
        """
        Handle UI actions for seeking to the previous execution of the selected address.
        """
        address = disassembler[self].get_current_address()
        rebased_address = self.reader.analysis.rebase_pointer(address)
        result = self.reader.seek_to_prev(rebased_address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            pmsg(f"Go to 0x{address:08x} failed, no previous executions of address")

    def interactive_first_execution(self):
        """
        Handle UI actions for seeking to the first execution of the selected address.
        """
        address = disassembler[self].get_current_address()
        rebased_address = self.reader.analysis.rebase_pointer(address)
        result = self.reader.seek_to_first(rebased_address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            pmsg(f"Go to 0x{address:08x} failed, no executions of address")

    def interactive_final_execution(self):
        """
        Handle UI actions for seeking to the final execution of the selected address.
        """
        address = disassembler[self].get_current_address()
        rebased_address = self.reader.analysis.rebase_pointer(address)
        result = self.reader.seek_to_final(rebased_address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            pmsg(f"Go to 0x{address:08x} failed, no executions of address")

    def _idx_changed(self, idx):
        """
        Handle a trace reader event indicating that the current IDX has changed.

        This will make the disassembler track with the PC/IP of the trace reader. 
        """
        dctx = disassembler[self]

        #
        # get a 'rebased' version of the current instruction pointer, which
        # should map to the disassembler / open database if it is a code
        # address that is known
        #

        bin_address = self.reader.rebased_ip

        #
        # if the code address is in a library / other unknown area that
        # cannot be renedered by the disassembler, then resolve the last
        # known trace 'address' within the database
        #

        if not dctx.is_mapped(bin_address):
            last_good_idx = self.reader.analysis.get_prev_mapped_idx(idx)
            if last_good_idx == -1:
                return # navigation is just not gonna happen...

            # fetch the last instruction pointer to fall within the trace
            last_good_trace_address = self.reader.get_ip(last_good_idx)

            # convert the trace-based instruction pointer to one that maps to the disassembler
            bin_address = self.reader.analysis.rebase_pointer(last_good_trace_address)

        # navigate the disassembler to a 'suitable' address based on the trace idx
        dctx.navigate(bin_address)
        disassembler.refresh_views()

    def _select_trace_file(self):
        """
        Prompt a file selection dialog, returning file selections.
        
        This will save & reuses the last known directory for subsequent calls.
        """

        if not self._last_directory:
            self._last_directory = disassembler[self].get_database_directory()

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(
            None,
            'Open trace file',
            self._last_directory,
            'All Files (*.*)'
        )
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filenames, _ = file_dialog.getOpenFileNames()

        #
        # remember the last directory we were in (parsed from a selected file)
        # for the next time the user comes to load trace files
        #

        if filenames:
            self._last_directory = os.path.dirname(filenames[0]) + os.sep

        # log the captured (selected) filenames from the dialog
        logger.debug("Captured filenames from file dialog:")
        for name in filenames:
            logger.debug(" - %s" % name)

        # return the captured filenames
        return filenames