import ctypes
import logging

#
# TODO: should probably cleanup / document this file a bit better
#

import ida_dbg
import ida_bytes
import ida_idaapi
import ida_kernwin
import idautils # Add import for idautils
import ida_lines
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

from tenet.core import TenetCore
from tenet.types import BreakpointEvent
from tenet.context import TenetContext
from tenet.util.misc import register_callback, notify_callback, is_plugin_dev
from tenet.util.qt import *

logger = logging.getLogger("Tenet.IDA.Integration")

IDA_GLOBAL_CTX = "blah this value doesn't matter"

#------------------------------------------------------------------------------
# IDA UI Integration
#------------------------------------------------------------------------------

class TenetIDA(TenetCore):
    """
    The plugin integration layer IDA Pro.
    """

    def __init__(self):

        #
        # icons
        #

        self._icon_id_file = ida_idaapi.BADADDR
        self._icon_id_next_execution = ida_idaapi.BADADDR
        self._icon_id_prev_execution = ida_idaapi.BADADDR

        #
        # event hooks
        #

        self._hooked = False
        
        self._ui_hooks = UIHooks()
        self._ui_hooks.get_lines_rendering_info = self._render_lines
        self._ui_hooks.finish_populating_widget_popup = self._popup_hook

        self._dbg_hooks = DbgHooks()
        self._dbg_hooks.dbg_bpt_changed = self._breakpoint_changed_hook

        #
        # we should always hook the UI early in dev mode as we will use UI
        # events to auto-launch a trace
        #

        if is_plugin_dev():
            self._ui_hooks.hook()

        #
        # callbacks
        #

        self._ui_breakpoint_changed_callbacks = []

        #
        # run disassembler-agnostic core initalization
        #

        super(TenetIDA, self).__init__()

        # Actions are installed via load() override

    def hook(self):
        if self._hooked:
            return
        self._hooked = True
        self._ui_hooks.hook()
        self._dbg_hooks.hook()

    def unhook(self):
        if not self._hooked:
            return
        self._hooked = False
        self._ui_hooks.unhook()
        self._dbg_hooks.unhook()

    def get_context(self, dctx, startup=True):
        """
        Get the plugin context for a given database.

        NOTE: since IDA can only have one binary / IDB open at a time, the
        dctx (database context) should always be IDA_GLOBAL_CTX.
        """
        assert dctx is IDA_GLOBAL_CTX
        self.palette.warmup()

        #
        # there should only ever be 'one' disassembler / IDB context at any
        # time for IDA. but if one does not exist yet, that means this is the
        # first time the user has interacted with the plugin for this session
        #

        if dctx not in self.contexts:

            # create a new 'plugin context' representing this IDB
            pctx = TenetContext(self, dctx)
            if startup:
                pctx.start()

            # save the created ctx for future calls
            self.contexts[dctx] = pctx

        # return the plugin context object for this IDB
        return self.contexts[dctx]

    def load(self):
        """Called by the loader when IDA is loading the plugin."""
        # Assuming TenetCore.load() exists and might do something important
        # If TenetCore.load is empty or doesn't exist, this super call can be removed.
        if hasattr(super(TenetIDA, self), 'load'):
             super(TenetIDA, self).load()
        self._install_actions()
        # Hooks might be better managed based on trace presence, but let's keep the existing logic for now.
        if is_plugin_dev(): # Keep existing dev mode hook logic from __init__
             self.hook()

    def unload(self):
        """Called by the loader when IDA is unloading the plugin."""
        self.unhook() # Unhook unconditionally on unload
        self._uninstall_actions()
        # Assuming TenetCore.unload() exists and might do something important
        if hasattr(super(TenetIDA, self), 'unload'):
            super(TenetIDA, self).unload()

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_LOAD_TRACE      = "tenet:load_trace"
    ACTION_FIRST_EXECUTION = "tenet:first_execution"
    ACTION_FINAL_EXECUTION = "tenet:final_execution"
    ACTION_NEXT_EXECUTION  = "tenet:next_execution"
    ACTION_PREV_EXECUTION  = "tenet:prev_execution"

    # LLDB Style Actions
    ACTION_STEP_OVER       = "tenet:step_over"
    ACTION_STEP_INTO       = "tenet:step_into"
    ACTION_STEP_OUT        = "tenet:step_out"
    ACTION_CONTINUE        = "tenet:continue"
    ACTION_PREV_INSN       = "tenet:prev_insn" # New action for previous instruction
    ACTION_PREV_INSN       = "tenet:prev_insn" # New action for previous instruction

    def _install_load_trace(self):

        # TODO: create a custom IDA icon 
        #icon_path = plugin_resource(os.path.join("icons", "load.png"))
        #icon_data = open(icon_path, "rb").read()
        #self._icon_id_file = ida_kernwin.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_LOAD_TRACE,                    # The action name
            "~T~enet trace file...",                   # The action text
            IDACtxEntry(self._interactive_load_trace), # The action handler
            None,                                      # Optional: action shortcut
            "Load a Tenet trace file",                 # Optional: tooltip
            -1                                         # Optional: the action icon
        )

        # register the action with IDA
        result = ida_kernwin.register_action(action_desc)
        # assert result, f"Failed to register '{action_desc.name}' action with IDA" # Temporarily disable assertion
        if not result:
             logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
             # Optionally raise error or return False depending on desired handling
             return False # Indicate failure
        logger.info(f"Successfully registered '{action_desc.name}' action.") # Log success

        # attach the action to the File-> dropdown menu *after* successful registration
        result_attach = ida_kernwin.attach_action_to_menu(
            "File/Load file/",       # Relative path of where to add the action
            self.ACTION_LOAD_TRACE,  # The action ID (see above)
            ida_kernwin.SETMENU_APP  # We want to append the action after ^
        )
        if not result_attach: # Check attach result too
             logger.error(f"Failed action attach {action_desc.name}")
             # Consider if failure to attach should prevent plugin load? Maybe just log.
             # Let's assume attaching the main load action to the menu is critical.
             return False
        logger.info(f"Successfully attached '{action_desc.name}' to menu.")
        return True # Indicate overall success for this action install (register + attach)

    def _install_next_execution(self):
        try: # Wrap in try-except to catch potential errors like icon loading
             icon_data = self.palette.gen_arrow_icon(self.palette.arrow_next, 0)
             self._icon_id_next_execution = ida_kernwin.load_custom_icon(data=icon_data)

             # describe a custom IDA UI action
             action_desc = ida_kernwin.action_desc_t(
                 self.ACTION_NEXT_EXECUTION,                        # The action name
                 "Go to next execution",                            # The action text
                 IDACtxEntry(self._interactive_next_execution),     # The action handler
                 None,                                              # Optional: action shortcut
                 "Go to the next execution of the current address", # Optional: tooltip
                 self._icon_id_next_execution                       # Optional: the action icon
             )

             # register the action with IDA
             result = ida_kernwin.register_action(action_desc)
             if not result:
                  logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
                  return False # Indicate failure
             logger.info(f"Successfully registered '{action_desc.name}' action.") # Log success
             return True # Indicate success
        except Exception as e:
             logger.error(f"Error during _install_next_execution: {e}")
             return False # Indicate failure
        result_attach = ida_kernwin.attach_action_to_menu(
            "File/Load file/",       # Relative path of where to add the action
            self.ACTION_LOAD_TRACE,  # The action ID (see above)
            ida_kernwin.SETMENU_APP  # We want to append the action after ^
        )
        if not result_attach: # Check attach result too
             logger.error(f"Failed action attach {action_desc.name}")
             # Consider if failure to attach should prevent plugin load? Maybe just log.
             return False # Or just log and return True if attaching is non-critical
        return True # Indicate overall success for this action install
        logger.info(f"Installed the '{action_desc.name}' menu entry")

    def _install_prev_execution(self):
        try:
             icon_data = self.palette.gen_arrow_icon(self.palette.arrow_prev, 180.0)
             self._icon_id_prev_execution = ida_kernwin.load_custom_icon(data=icon_data)

             # describe a custom IDA UI action
             action_desc = ida_kernwin.action_desc_t(
                 self.ACTION_PREV_EXECUTION,                            # The action name
                 "Go to previous execution",                            # The action text
                 IDACtxEntry(self._interactive_prev_execution),         # The action handler
                 None,                                                  # Optional: action shortcut
                 "Go to the previous execution of the current address", # Optional: tooltip
                 self._icon_id_prev_execution                           # Optional: the action icon
             )

             # register the action with IDA
             result = ida_kernwin.register_action(action_desc)
             # assert result, f"Failed to register '{action_desc.name}' action with IDA" # Remove assertion
             if not result:
                  logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
                  return False # Indicate failure
             logger.info(f"Successfully registered '{action_desc.name}' action.") # Log success
             return True # Indicate success
        except Exception as e:
             logger.error(f"Error during _install_prev_execution: {e}")
             return False # Indicate failure

    def _install_first_execution(self):
        try:
             # describe a custom IDA UI action
             action_desc = ida_kernwin.action_desc_t(
                 self.ACTION_FIRST_EXECUTION,                        # The action name
                 "Go to first execution",                            # The action text
                 IDACtxEntry(self._interactive_first_execution),     # The action handler
                 None,                                               # Optional: action shortcut
                 "Go to the first execution of the current address", # Optional: tooltip
                 -1                                                  # Optional: the action icon
             )

             # register the action with IDA
             result = ida_kernwin.register_action(action_desc)
             # assert result, f"Failed to register '{action_desc.name}' action with IDA" # Remove assertion
             if not result:
                  logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
                  return False # Indicate failure
             logger.info(f"Successfully registered '{action_desc.name}' action.") # Log success
             return True # Indicate success
        except Exception as e:
             logger.error(f"Error during _install_first_execution: {e}")
             return False # Indicate failure

    def _install_final_execution(self):
        try:
             # describe a custom IDA UI action
             action_desc = ida_kernwin.action_desc_t(
                 self.ACTION_FINAL_EXECUTION,                        # The action name
                 "Go to final execution",                            # The action text
                 IDACtxEntry(self._interactive_final_execution),     # The action handler
                 None,                                               # Optional: action shortcut
                 "Go to the final execution of the current address", # Optional: tooltip
                 -1                                                  # Optional: the action icon
             )

             # register the action with IDA
             result = ida_kernwin.register_action(action_desc)
             # assert result, f"Failed to register '{action_desc.name}' action with IDA" # Remove assertion
             if not result:
                  logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
                  return False # Indicate failure
             logger.info(f"Successfully registered '{action_desc.name}' action.") # Log success
             return True # Indicate success
        except Exception as e:
             logger.error(f"Error during _install_final_execution: {e}")
             return False # Indicate failure

    def _uninstall_load_trace(self):

        logger.info("Removing the 'Tenet trace file...' menu entry...")

        # remove the entry from the File-> menu
        result = ida_kernwin.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_TRACE
        )
        if not result:
            logger.warning("Failed to detach action from menu...")
            return False

        # unregister the action
        result = ida_kernwin.unregister_action(self.ACTION_LOAD_TRACE)
        if not result:
            logger.warning("Failed to unregister action...")
            return False

        # delete the entry's icon
        #ida_kernwin.free_custom_icon(self._icon_id_file) # TODO
        self._icon_id_file = ida_idaapi.BADADDR

        logger.info("Successfully removed the menu entry!")
        return True

    def _uninstall_next_execution(self):
        result = self._uninstall_action(self.ACTION_NEXT_EXECUTION, self._icon_id_next_execution)
        self._icon_id_next_execution = ida_idaapi.BADADDR
        return result
        
    def _uninstall_prev_execution(self):
        result = self._uninstall_action(self.ACTION_PREV_EXECUTION, self._icon_id_prev_execution)
        self._icon_id_prev_execution = ida_idaapi.BADADDR
        return result
        
    def _uninstall_first_execution(self):
        return self._uninstall_action(self.ACTION_FIRST_EXECUTION)
        
    def _uninstall_final_execution(self):
        return self._uninstall_action(self.ACTION_FINAL_EXECUTION)

    def _uninstall_action(self, action, icon_id=ida_idaapi.BADADDR):

        result = ida_kernwin.unregister_action(action)
        if not result:
            logger.warning(f"Failed to unregister {action}...")
            return False

        if icon_id != ida_idaapi.BADADDR:
            ida_kernwin.free_custom_icon(icon_id)

        logger.info(f"Uninstalled the {action} menu entry")
        return True

    def _install_step_over(self):
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_STEP_OVER,
            "Step Over (Tenet)",
            IDACtxEntry(self._handle_step_over),
            "Ctrl+Shift+N", # Shortcut with Ctrl+Shift modifier
            "Navigate trace forward, stepping over calls",
            -1
        )
        result = ida_kernwin.register_action(action_desc)
        # assert result, f"Failed to register '{action_desc.name}' action" # Remove assertion
        if not result:
             logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
             return False # Indicate failure
        logger.info(f"Successfully registered '{action_desc.name}' action with shortcut 'N'.") # Log success
        return True # Indicate success

    def _install_step_into(self):
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_STEP_INTO,
            "Step Into (Tenet)",
            IDACtxEntry(self._handle_step_into),
            "Ctrl+Shift+S", # Shortcut with Ctrl+Shift modifier
            "Navigate trace forward, stepping into calls",
            -1
        )
        result = ida_kernwin.register_action(action_desc)
        # assert result, f"Failed to register '{action_desc.name}' action" # Remove assertion
        if not result:
             logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
             return False # Indicate failure
        logger.info(f"Successfully registered '{action_desc.name}' action with shortcut 'S'.") # Log success
        return True # Indicate success

    def _install_step_out(self):
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_STEP_OUT,
            "Step Out (Tenet)",
            IDACtxEntry(self._handle_step_out),
            "Ctrl+Shift+F", # Shortcut with Ctrl+Shift modifier
            "Navigate trace forward until the current function returns",
            -1
        )
        result = ida_kernwin.register_action(action_desc)
        # assert result, f"Failed to register '{action_desc.name}' action" # Remove assertion
        if not result:
             logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
             return False # Indicate failure
        logger.info(f"Successfully registered '{action_desc.name}' action with shortcut 'F'.") # Log success
        return True # Indicate success

    def _install_continue(self):
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_CONTINUE,
            "Continue (Tenet)",
            IDACtxEntry(self._handle_continue),
            "Ctrl+Shift+C", # Shortcut with Ctrl+Shift modifier
            "Navigate trace forward to the next breakpoint or end",
            -1
        )
        result = ida_kernwin.register_action(action_desc)
        # assert result, f"Failed to register '{action_desc.name}' action" # Remove assertion
        if not result:
             logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
             return False # Indicate failure
        logger.info(f"Successfully registered '{action_desc.name}' action with shortcut 'C'.") # Log success
        return True # Indicate success

    def _install_prev_insn(self):
        """Install the 'Previous Instruction' action."""
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_PREV_INSN,
            "Previous Instruction (Tenet)",
            IDACtxEntry(self._handle_prev_insn),
            "Ctrl+Shift+B", # Shortcut
            "Navigate trace backward one instruction",
            -1 # Optional: Add an icon later if desired
        )
        result = ida_kernwin.register_action(action_desc)
        if not result:
             logger.error(f"Failed to register '{action_desc.name}' action with IDA. Result: {result}")
             return False
        logger.info(f"Successfully registered '{action_desc.name}' action with shortcut 'Ctrl+Shift+B'.")
        return True

    def _uninstall_step_over(self):
        return self._uninstall_action(self.ACTION_STEP_OVER)

    def _uninstall_step_into(self):
        return self._uninstall_action(self.ACTION_STEP_INTO)

    def _uninstall_step_out(self):
        return self._uninstall_action(self.ACTION_STEP_OUT)

    def _uninstall_continue(self):
        return self._uninstall_action(self.ACTION_CONTINUE)

    def _uninstall_prev_insn(self):
        """Uninstall the 'Previous Instruction' action."""
        return self._uninstall_action(self.ACTION_PREV_INSN)

    def _uninstall_prev_insn(self):
        """Uninstall the 'Previous Instruction' action."""
        return self._uninstall_action(self.ACTION_PREV_INSN)

    def _install_actions(self):
        """Install all IDA actions for Tenet. Attempts to unregister first."""
        logger.info("Attempting to install Tenet actions...")
        # Attempt to unregister actions first to handle potential stale registrations
        # We ignore the return value of uninstall, as it might fail if the action wasn't registered yet.
        self._uninstall_load_trace()
        self._uninstall_next_execution()
        self._uninstall_prev_execution()
        self._uninstall_first_execution()
        self._uninstall_final_execution()
        # Also unregister new actions if they exist
        self._uninstall_step_over()
        self._uninstall_step_into()
        self._uninstall_step_out()
        self._uninstall_continue()
        self._uninstall_prev_insn() # Add uninstall for previous instruction
        self._uninstall_prev_insn() # Add uninstall for previous instruction

        # Now attempt to install actions
        results = []
        results.append(self._install_load_trace())
        # Need to modify install methods to not assert, just return False and log
        results.append(self._install_next_execution())
        results.append(self._install_prev_execution())
        results.append(self._install_first_execution())
        results.append(self._install_final_execution())

        # Install new actions
        results.append(self._install_step_over())
        results.append(self._install_step_into())
        results.append(self._install_step_out())
        results.append(self._install_continue())
        results.append(self._install_prev_insn()) # Add install for previous instruction
        
        # Check if essential actions failed (e.g., load trace)
        if not results[0]: # Check if the first essential action failed
            logger.error("Failed to install essential action 'tenet:load_trace'.")
            # Even if essential fails, log status of others for debugging
            for i, res in enumerate(results[1:], 1):
                 action_name = [ # List corresponds to install order above
                     "tenet:next_execution", "tenet:prev_execution",
                     "tenet:first_execution", "tenet:final_execution"
                 ][i-1] # Adjust index
                 if not res: logger.warning(f"Also failed to install action '{action_name}'.")
            return False # Indicate critical failure

        # Log success/failure of other core actions if they failed
        all_core_succeeded = all(results[:5]) # Check first 5 core actions
        if not all_core_succeeded:
             logger.warning("One or more non-essential core actions failed to install.")
             # List specific failures
             core_actions = ["tenet:load_trace", "tenet:next_execution", "tenet:prev_execution",
                             "tenet:first_execution", "tenet:final_execution"]
             for name, success in zip(core_actions, results[:5]):
                 if not success: logger.warning(f" - Failed: {name}")
        
        logger.info("Finished installing all Tenet actions.")
        return True # Indicate overall success (essential actions loaded)

    def _uninstall_actions(self):
        """Uninstall all IDA actions for Tenet."""
        self._uninstall_load_trace()
        self._uninstall_next_execution()
        self._uninstall_prev_execution()
        self._uninstall_first_execution()
        self._uninstall_final_execution()
        self._uninstall_step_over()
        self._uninstall_step_into()
        self._uninstall_step_out()
        self._uninstall_continue()
        self._uninstall_prev_insn() # Add uninstall for previous instruction

    #--------------------------------------------------------------------------
    # UI Event Handlers
    #--------------------------------------------------------------------------

    def _breakpoint_changed_hook(self, code, bpt):
        """
        (Event) Breakpoint changed.
        """

        if code == ida_dbg.BPTEV_ADDED:
            self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.ADDED)

        elif code == ida_dbg.BPTEV_CHANGED:
            if bpt.enabled():
                self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.ENABLED)
            else:
                self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.DISABLED)

        elif code == ida_dbg.BPTEV_REMOVED:
            self._notify_ui_breakpoint_changed(bpt.ea, BreakpointEvent.REMOVED)

        return 0

    def _popup_hook(self, widget, popup):
        """
        (Event) IDA is about to show a popup for the given TWidget.
        """

        # TODO: return if plugin/trace is not active
        pass

        # fetch the (IDA) window type (eg, disas, graph, hex ...)
        view_type = ida_kernwin.get_widget_type(widget)

        # only attach these context items to popups in disas views
        if view_type == ida_kernwin.BWN_DISASMS:

            # prep for some shady hacks
            p_qmenu = ctypes.cast(int(popup), ctypes.POINTER(ctypes.c_void_p))[0]
            qmenu = sip.wrapinstance(int(p_qmenu), QtWidgets.QMenu)

            #
            # inject and organize the Tenet plugin actions
            #

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_NEXT_EXECUTION,  # The action ID (see above)
                "Rename",                    # Relative path of where to add the action
                ida_kernwin.SETMENU_APP      # We want to append the action after ^
            )

            #
            # this is part of our bodge to inject a plugin action submenu
            # at a specific location in the QMenu, cuz I don't think it's
            # actually possible with the native IDA API's (for groups...)
            #

            for action in qmenu.actions():
                if action.text() == "Go to next execution":

                    # inject a group for the exta 'go to' actions
                    goto_submenu = QtWidgets.QMenu("Go to...")
                    qmenu.insertMenu(action, goto_submenu)

                    # hold a Qt ref of the submenu so it doesn't GC
                    self.__goto_submenu = goto_submenu
                    break

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_FIRST_EXECUTION,     # The action ID (see above)
                "Go to.../",                     # Relative path of where to add the action
                ida_kernwin.SETMENU_APP          # We want to append the action after ^
            )

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_FINAL_EXECUTION,     # The action ID (see above)
                "Go to.../",                     # Relative path of where to add the action
                ida_kernwin.SETMENU_APP          # We want to append the action after ^
            )

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_PREV_EXECUTION,  # The action ID (see above)
                "Rename",                    # Relative path of where to add the action
                ida_kernwin.SETMENU_APP      # We want to append the action after ^
            )

            #
            # inject a seperator to help insulate our plugin action group
            #

            for action in qmenu.actions():
                if action.text() == "Go to previous execution":
                    qmenu.insertSeparator(action)
                    break

    def _render_lines(self, lines_out, widget, lines_in):
        """
        (Event) IDA is about to render code viewer lines.
        """
        widget_type = ida_kernwin.get_widget_type(widget)
        # --- DEBUG LOGGING START ---
        hexrays_status = "Available" if ida_hexrays else "Not Available"
        logger.debug(f"_render_lines called for widget_type: {widget_type}, ida_hexrays: {hexrays_status}")
        # --- DEBUG LOGGING END ---

        ctx = self.get_context(IDA_GLOBAL_CTX, startup=False)
        if not ctx or not ctx.reader:
            # logger.debug("_render_lines: No active context or reader, returning.") # Keep logs focused
            return

        # Compute the colors needed for highlighting
        address_to_color = self._compute_highlight_colors(ctx)
        if not address_to_color:
            # logger.debug("_render_lines: No colors to highlight, returning.") # Keep logs focused
            return
        # logger.debug(f"_render_lines: Computed colors: { {hex(k): v for k,v in address_to_color.items()} }") # DEBUG: Very verbose

        # Apply highlighting based on the view type
        if widget_type == ida_kernwin.BWN_DISASM:
            # logger.debug("_render_lines: Highlighting disassembly.")
            self._highlight_disassembly(lines_out, lines_in, address_to_color)
        elif ida_hexrays and widget_type == ida_kernwin.BWN_PSEUDOCODE:
            logger.debug("_render_lines: Highlighting pseudocode.")
            self._highlight_pseudocode(lines_out, widget, lines_in, address_to_color)
        else:
            # logger.debug(f"_render_lines: Ignoring widget type {widget_type}.") # DEBUG: Can be noisy
            pass

        return

    def _compute_highlight_colors(self, ctx):
        """
        Compute the address-to-color mapping for the current trace state.
        Returns a dictionary {address: color} or None if no reader.
        """
        if not ctx or not ctx.reader:
            return None

        trail_length = 6
        address_to_color = {}

        # Colors from palette
        forward_color = self.palette.trail_forward
        current_color_qt = self.palette.trail_current
        backward_color = self.palette.trail_backward

        # Convert current color to IDA format (0xAABBGGRR)
        r, g, b, _ = current_color_qt.getRgb()
        current_color_ida = 0xFF << 24 | b << 16 | g << 8 | r

        # Determine step over state
        step_over = False
        modifiers = QtGui.QGuiApplication.keyboardModifiers()
        step_over = bool(modifiers & QtCore.Qt.ShiftModifier)

        # Get IPs for trails
        forward_ips = ctx.reader.get_next_ips(trail_length, step_over)
        backward_ips = ctx.reader.get_prev_ips(trail_length, step_over)

        # Process trails
        trails_data = [
            (backward_ips, backward_color),
            (forward_ips, forward_color)
        ]

        for addresses, base_color in trails_data:
            for i, address in enumerate(addresses):
                percent = 1.0 - ((trail_length - i) / trail_length)
                r, g, b, _ = base_color.getRgb()
                ida_color = b << 16 | g << 8 | r
                ida_color |= (0xFF - int(0xFF * percent)) << 24 # Apply alpha fade

                rebased_address = ctx.reader.analysis.rebase_pointer(address)
                if rebased_address != ida_idaapi.BADADDR:
                    address_to_color[rebased_address] = ida_color

        # Handle current address
        current_address_rebased = ctx.reader.rebased_ip
        if not ida_bytes.is_mapped(current_address_rebased):
            last_good_idx = ctx.reader.analysis.get_prev_mapped_idx(ctx.reader.idx)
            if last_good_idx != -1:
                last_good_trace_address = ctx.reader.get_ip(last_good_idx)
                current_address_rebased = ctx.reader.analysis.rebase_pointer(last_good_trace_address)

        if current_address_rebased != ida_idaapi.BADADDR:
            address_to_color[current_address_rebased] = current_color_ida # Override trail color if current

        return address_to_color

    def _highlight_disassembly(self, lines_out, lines_in, address_to_color):
        """
        Apply highlighting to IDA Disassembly view lines.
        """
        # Iterate through the lines provided by IDA
        for section in lines_in.sections_lines:
            for line in section:
                # Get the address associated with the line
                address = line.at.toea()

                # Check if this address needs highlighting
                color = address_to_color.get(address)
                if color is not None:
                    # Create and add the rendering entry
                    try:
                        entry = ida_kernwin.line_rendering_output_entry_t(
                            line,
                            ida_kernwin.LROEF_FULL_LINE,
                            color
                        )
                        lines_out.entries.push_back(entry)
                    except Exception as e:
                        logger.error(f"Error creating/adding disassembly entry for ea {address:#x}: {e}")

    def _highlight_pseudocode(self, lines_out, widget, lines_in, address_to_color):
        """
        Apply highlighting to IDA Pseudocode view lines.
        """
        logger.debug("_highlight_pseudocode: Entered.")
        if not ida_hexrays:
            logger.debug("_highlight_pseudocode: Hex-Rays not available.")
            return

        try:
            # Get vdui and cfunc objects
            vdui = ida_hexrays.get_widget_vdui(widget)
            if not vdui:
                logger.debug("_highlight_pseudocode: Failed to get vdui.")
                return
            cfunc = vdui.cfunc
            if not cfunc:
                logger.debug("_highlight_pseudocode: Failed to get cfunc.")
                return
            logger.debug(f"_highlight_pseudocode: Got vdui and cfunc for func @ {cfunc.entry_ea:#x}")

            # Pre-create citem_t objects for reuse
            head = ida_hexrays.ctree_item_t()
            item = ida_hexrays.ctree_item_t()
            tail = ida_hexrays.ctree_item_t()

            # Iterate through the lines provided by IDA
            for section in lines_in.sections_lines:
                for tw_line in section:
                    if tw_line is None: continue

                    place = tw_line.at
                    if place is None: continue

                    ea = ida_idaapi.BADADDR
                    line_text_raw = tw_line.line # Get SWIG proxy directly

                    # Avoid processing if line is empty or None
                    if not line_text_raw: continue

                    # Attempt to get the address associated with the line item
                    try:
                        # No need to manually clean tags for get_line_item based on typical usage
                        # clean_line_text = ida_lines.tag_remove(line_text_raw.c_str()) # Potential optimization: avoid if not needed
                        # if not clean_line_text: continue

                        lnnum = place.lnnum
                        is_ctree_line = lnnum >= cfunc.hdrlines

                        # Use raw line text (SWIG proxy) directly with get_line_item
                        found = cfunc.get_line_item(line_text_raw, 0, is_ctree_line, head, item, tail)

                        if found:
                            # Check item first, ensuring 'ea' attribute exists and is valid
                            if item.citype != ida_hexrays.VDI_NONE and hasattr(item, 'ea') and item.ea != ida_idaapi.BADADDR:
                                ea = item.ea
                            # If item didn't yield a valid ea, check head
                            elif head.citype != ida_hexrays.VDI_NONE and hasattr(head, 'ea') and head.ea != ida_idaapi.BADADDR:
                                ea = head.ea
                            # Add tail check if necessary, with hasattr check:
                            # elif tail.citype != ida_hexrays.VDI_NONE and hasattr(tail, 'ea') and tail.ea != ida_idaapi.BADADDR:
                            #     ea = tail.ea

                    except Exception as e:
                        # Log error but continue processing other lines
                        logger.warning(f"Error getting citem for pseudocode line {lnnum}: {e}")
                        continue # Skip to next line on error

                    # If we couldn't map the line to a valid address, skip it
                    if ea == ida_idaapi.BADADDR:
                        continue

                    # Check if this address needs highlighting
                    color = address_to_color.get(ea)
                    if color is not None:
                        logger.debug(f"_highlight_pseudocode: Found color {color:#x} for ea {ea:#x} on line {lnnum}")
                        # Create and add the rendering entry
                        try:
                            entry = ida_kernwin.line_rendering_output_entry_t(
                                tw_line,
                                ida_kernwin.LROEF_FULL_LINE,
                                color
                            )
                            lines_out.entries.push_back(entry)
                            logger.debug(f"_highlight_pseudocode: Added entry for line {lnnum}, ea {ea:#x}")
                            # NOTE: Potential lifecycle management needed for 'entry' if issues arise
                        except Exception as e:
                            logger.error(f"Error creating/adding pseudocode entry for ea {ea:#x}: {e}")
                    # else: # DEBUG: Log if no color found for a valid ea
                    #     logger.debug(f"_highlight_pseudocode: No color found for ea {ea:#x} on line {lnnum}")

        except Exception as e:
            logger.error(f"Error in _highlight_pseudocode: {e}", exc_info=True) # Add traceback

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def ui_breakpoint_changed(self, callback):
        register_callback(self._ui_breakpoint_changed_callbacks, callback)

    def _notify_ui_breakpoint_changed(self, address, code):
        notify_callback(self._ui_breakpoint_changed_callbacks, address, code)

    #--------------------------------------------------------------------------
    # Action Handlers
    #--------------------------------------------------------------------------

    def _handle_step_over(self, dctx):
        """Handle the 'Step Over' action."""
        ctx = self.get_context(dctx, startup=False)
        if not ctx or not ctx.reader:
            ida_kernwin.warning("Tenet: Trace not active.")
            return
        # Check if disassembler context (dctx) is available in the reader,
        # as it's required by the reader's step_over logic.
        if not ctx.reader.dctx:
             ida_kernwin.warning("Tenet: Disassembler context needed for Step Over is not available in TraceReader.")
             # Fallback to simple step-into might be an option, but for clarity, just warn and return.
             # ctx.reader.step_forward(n=1, step_over=False) # Optional fallback
             return

        logger.info("Step Over action triggered")
        try:
            # Use the existing step_forward method from TraceReader with step_over=True
            # This method internally handles seeking and should trigger necessary callbacks (_notify_idx_changed)
            ctx.reader.step_forward(n=1, step_over=True)
            # Assuming the seek within step_forward triggers the UI update via _notify_idx_changed callback.
            # If not, ctx.notify_ui() might be needed here.
            logger.info(f"Step Over executed. New index: {ctx.reader.idx}")
        except Exception as e:
            logger.exception("Error during Step Over:")
            ida_kernwin.warning(f"Tenet: Error during step over: {e}")

    def _handle_step_into(self, dctx):
        """Handle the 'Step Into' action."""
        ctx = self.get_context(dctx, startup=False)
        if not ctx or not ctx.reader:
            ida_kernwin.warning("Tenet trace not active.")
            return

        logger.info("Step Into action triggered")
        try:
            current_idx = ctx.reader.idx
            # Use trace.length property instead of len(trace)
            if current_idx + 1 < ctx.reader.trace.length:
                target_idx = current_idx + 1
                ctx.reader.seek(target_idx)
                # The seek operation should trigger the necessary callbacks
                # (e.g., _notify_idx_changed in TraceReader, listened to by TenetContext)
                # which in turn should call refresh_views --> ida_kernwin.refresh_idaview_anyway().
                # No explicit refresh call is needed here if the callback chain is working correctly.
                logger.info(f"Stepped into index {target_idx}")
            else:
                ida_kernwin.info("Tenet: Already at the end of the trace.")
        except Exception as e:
            logger.exception("Error during Step Into:")
            ida_kernwin.warning(f"Tenet: Error during step into: {e}")

    def _handle_step_out(self, dctx):
        """Handle the 'Step Out' (Finish) action."""
        ctx = self.get_context(dctx, startup=False)
        if not ctx or not ctx.reader:
            ida_kernwin.warning("Tenet: Trace not active.")
            return
        # Check if disassembler context (dctx) is available in the reader,
        # as it's required by the reader's find_return_index logic.
        if not ctx.reader.dctx:
             ida_kernwin.warning("Tenet: Disassembler context needed for Step Out is not available in TraceReader.")
             return

        logger.info("Step Out action triggered")
        try:
            start_idx = ctx.reader.idx
            target_idx = ctx.reader.find_return_index(start_idx)

            if target_idx != -1:
                # seek should trigger the idx_changed callback for UI updates
                ctx.reader.seek(target_idx)
                logger.info(f"Step Out executed. New index: {target_idx}")
            # else: # Handle case where return index wasn't found
                # The find_return_index method in the reader should ideally log
                # the reason (e.g., end of trace reached, function context unknown).
                # An optional ida_kernwin.info message could be added here if desired.
                # logger.info("Step Out could not find return index.")

        except Exception as e:
            logger.exception("Error during Step Out:")
            ida_kernwin.warning(f"Tenet: Error during step out: {e}")

    def _handle_prev_insn(self, dctx):
        """Handle the 'Previous Instruction' action."""
        ctx = self.get_context(dctx, startup=False)
        if not ctx or not ctx.reader:
            ida_kernwin.warning("Tenet: Trace not active.")
            return

        logger.info("Previous Instruction action triggered")
        try:
            current_idx = ctx.reader.idx
            if current_idx > 0:
                target_idx = current_idx - 1
                ctx.reader.seek(target_idx)
                # Assuming seek triggers UI update via callback (_notify_idx_changed -> _idx_changed)
                logger.info(f"Stepped back to index {target_idx}")
            else:
                ida_kernwin.info("Tenet: Already at the start of the trace.")
        except Exception as e:
            logger.exception("Error during Previous Instruction:")
            ida_kernwin.warning(f"Tenet: Error during previous instruction: {e}")

    def _handle_continue(self, dctx):
        """Handle the 'Continue' action."""
        ctx = self.get_context(dctx, startup=False)
        if not ctx or not ctx.reader:
            ida_kernwin.warning("Tenet: Trace not active.")
            return
        # Analysis module is needed for address conversion
        if not ctx.reader.analysis:
             ida_kernwin.warning("Tenet: Trace analysis module not available for Continue.")
             return
        # Ensure ida_dbg is available
        if not ida_dbg:
             logger.error("ida_dbg module not available for breakpoint handling.")
             ida_kernwin.warning("Tenet: Could not access IDA debugger functions.")
             return

        logger.info("Continue action triggered")
        try:
            # 1. Get enabled breakpoints from IDA using the original get_bpt(i, bpt) loop with detailed logging
            ida_breakpoints = set()
            bpt = ida_dbg.bpt_t()
            num_bpts = ida_dbg.get_bpt_qty()
            logger.debug(f"Checking {num_bpts} breakpoints using ida_dbg.getn_bpt(i, bpt)...")
            for i in range(num_bpts):
                # Use getn_bpt to get breakpoint by index i
                if ida_dbg.getn_bpt(i, bpt):
                    # Log details for every breakpoint found
                    is_enabled_flag = bool(bpt.flags & ida_dbg.BPT_ENABLED)
                    logger.debug(f"  Index {i}: Addr=0x{bpt.ea:X}, Flags=0x{bpt.flags:X}, IsEnabledFlagCheck={is_enabled_flag}")
                    # Ensure the breakpoint address is valid AND check the enabled flag
                    if bpt.ea != ida_idaapi.BADADDR and is_enabled_flag:
                        logger.debug(f"    -> Adding active breakpoint 0x{bpt.ea:X}")
                        ida_breakpoints.add(bpt.ea)
                else:
                    logger.warning(f"  Index {i}: ida_dbg.get_bpt() failed.")
            logger.debug(f"Finished checking breakpoints. Found {len(ida_breakpoints)} active breakpoints.")

            if not ida_breakpoints:
                 ida_kernwin.info("Tenet: No active IDA breakpoints found.")
                 # Standard behavior is often to run to end if no breakpoints.
                 logger.info("Continuing to end of trace as no breakpoints are set.")
                 ctx.reader.seek(ctx.reader.trace.length - 1)
                 return

            # 2. Convert IDA addresses (rebased) to trace addresses (original)
            trace_breakpoints = set()
            analysis = ctx.reader.analysis
            for bp_ea in ida_breakpoints:
                 try:
                      # unrebase_pointer might return None or raise if address is invalid/unmappable
                      unrebased_addr = analysis.unrebase_pointer(bp_ea)
                      if unrebased_addr is not None:
                           logger.debug(f"Mapped IDA BP 0x{bp_ea:X} to Trace BP 0x{unrebased_addr:X}")
                           trace_breakpoints.add(unrebased_addr)
                      else:
                           logger.warning(f"Could not unrebase breakpoint address 0x{bp_ea:X} to trace space.")
                 except Exception as e:
                      logger.warning(f"Error unrebaseing breakpoint address 0x{bp_ea:X}: {e}")

            if not trace_breakpoints:
                 ida_kernwin.info("Tenet: Could not map any active breakpoints to trace space.")
                 # Continue to end if no mappable breakpoints found
                 logger.info("Continuing to end of trace as no breakpoints mapped to trace.")
                 ctx.reader.seek(ctx.reader.trace.length - 1)
                 return

            logger.debug(f"Searching for trace breakpoints: { {hex(bp) for bp in trace_breakpoints} }")

            # 3. Find the next execution index hitting one of these trace breakpoints
            start_idx = ctx.reader.idx
            target_idx = ctx.reader.find_next_breakpoint_index(start_idx, trace_breakpoints)

            # 4. Seek to the found index or end of trace
            if target_idx != -1:
                ctx.reader.seek(target_idx)
                logger.info(f"Continued to breakpoint at index {target_idx}")
                ida_kernwin.info(f"Tenet: Continued to breakpoint at 0x{ctx.reader.get_ip(target_idx):X} (Index: {target_idx})")
            else:
                # If no breakpoint found, continue to the end of the trace
                logger.info("No further breakpoints found. Continuing to end of trace.")
                ctx.reader.seek(ctx.reader.trace.length - 1) # Seek to the last index
                ida_kernwin.info("Tenet: No further breakpoints found, continued to end of trace.")

        except Exception as e:
            logger.exception("Error during Continue:")
            ida_kernwin.warning(f"Tenet: Error during continue: {e}")

#------------------------------------------------------------------------------
# IDA UI Helpers
#------------------------------------------------------------------------------

class IDACtxEntry(ida_kernwin.action_handler_t):
    """
    A minimal context menu entry class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        super(IDACtxEntry, self).__init__()
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.

        NOTE: We pass 'None' to the action function to act as the '
        """
        self.action_function(IDA_GLOBAL_CTX)
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return ida_kernwin.AST_ENABLE_ALWAYS

#------------------------------------------------------------------------------
# IDA UI Event Hooks
#------------------------------------------------------------------------------

class DbgHooks(ida_dbg.DBG_Hooks):
    def dbg_bpt_changed(self, code, bpt):
        pass

class UIHooks(ida_kernwin.UI_Hooks):
    def get_lines_rendering_info(self, lines_out, widget, lines_in):
        pass
    def ready_to_run(self):
        pass
    def finish_populating_widget_popup(self, widget, popup):
        pass