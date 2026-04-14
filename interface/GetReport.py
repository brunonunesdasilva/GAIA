import os
import shutil
from pathlib import Path

from interface.icon_utils import get_window_icon
from PySide6.QtWidgets import (QDialog, QTableWidgetItem, QAbstractItemView, QHeaderView, QFileDialog)
from interface.AlertWindow import AlertWindow
from interface.base_windows.get_report import GetReportDialog
from backend.classes.Database import Database
import sqlite3

class GetReport(QDialog, GetReportDialog):
    def __init__(self) -> None:
        super(GetReport, self).__init__()
        self.setupUi(self)
        self.setWindowTitle('Laudos cadastrados')
        self.setWindowIcon(get_window_icon())
        self.report_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.report_table.verticalHeader().setVisible(False)
        self.report_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.report_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.report_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.report_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.copy_button.clicked.connect(self.make_copy)
        self.upload_button.clicked.connect(self.upload_signed_pdf)
        self.publish_button.clicked.connect(self.publish_report)
        self.remove_button.clicked.connect(self.remove_report)
        self.refresh_table()

    def refresh_table(self) -> None:
        db = Database()
        reports: list[sqlite3.Row] = db.get_report_info()
        reports = sorted(
            [report for report in (reports or []) if report['id'] is not None],
            key=lambda item: int(item['id']),
            reverse=True,
        )
        self.report_table.setRowCount(0)
        for report in reports:
            row_position: int = self.report_table.rowCount()
            self.report_table.insertRow(row_position)
            self.report_table.setItem(row_position, 0, QTableWidgetItem(str(report['id'])))
            self.report_table.setItem(row_position, 1, QTableWidgetItem(str(report['requester_name'])))
            self.report_table.setItem(row_position, 2, QTableWidgetItem(str(report['date'])))
            self.report_table.setItem(row_position, 3, QTableWidgetItem(str(report['property'])))

    def make_copy(self) -> None:
        selected_items: list[QTableWidgetItem] = self.report_table.selectedIndexes()
        if len(selected_items) == 0:
            widget: AlertWindow = AlertWindow("Você deve selecionar um laudo para copiar.")
            widget.exec()
            return
        for data in selected_items:
            if data.row() != selected_items[0].row():
                widget: AlertWindow = AlertWindow("Você só pode copiar um laudo por vez.")
                widget.exec()
                return
        row: int = selected_items[0].row()
        id_text = self.report_table.item(row, 0).text()
        try:
            id_val: int = int(id_text)
        except (TypeError, ValueError):
            widget: AlertWindow = AlertWindow("Laudo selecionado sem ID válido.")
            widget.exec()
            return
        file_path = self.open_save_dialog()
        script_path: Path = Path(__file__).resolve()
        backup_path: Path = script_path.parent.parent / "reports" / f"Laudo - {id_val}.pdf"
        try:
            shutil.copy(backup_path, file_path)
            widget: AlertWindow = AlertWindow("Cópia feita com sucesso!")
            widget.exec()
        except FileNotFoundError:
            widget: AlertWindow = AlertWindow(f"Arquivo de laudo não encontrado: {backup_path}")
            widget.exec()
        except Exception as e:
            widget: AlertWindow = AlertWindow(f"Erro ao copiar laudo: {str(e)}")
            widget.exec()

    def open_save_dialog(self) -> str:
        filename: QFileDialog.getSaveFileName = QFileDialog.getSaveFileName(filter="*.pdf")
        return filename[0]
    
    def upload_signed_pdf(self) -> None:
        """Faz upload do PDF assinado para substituir o laudo original"""
        selected_items: list[QTableWidgetItem] = self.report_table.selectedIndexes()
        
        if len(selected_items) == 0:
            widget: AlertWindow = AlertWindow("Você deve selecionar um laudo para fazer upload.")
            widget.exec()
            return
        
        # Verifica se selecionou apenas uma linha
        for data in selected_items:
            if data.row() != selected_items[0].row():
                widget: AlertWindow = AlertWindow("Você só pode fazer upload em um laudo por vez.")
                widget.exec()
                return
        
        row: int = selected_items[0].row()
        id_text = self.report_table.item(row, 0).text()
        
        try:
            laudo_id: int = int(id_text)
        except (TypeError, ValueError):
            widget: AlertWindow = AlertWindow("Laudo selecionado sem ID válido.")
            widget.exec()
            return
        
        # Abre diálogo para selecionar arquivo PDF
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecione o PDF Assinado",
            "",
            "Arquivos PDF (*.pdf)"
        )
        
        if not file_path:
            return  # Usuário cancelou
        
        # Confirmação
        from PySide6.QtWidgets import QMessageBox
        confirm = QMessageBox()
        confirm.setIcon(QMessageBox.Question)
        confirm.setWindowTitle("Confirmar Upload")
        confirm.setText(f"Deseja substituir o PDF do laudo ID {laudo_id}?")
        confirm.setInformativeText(f"Arquivo selecionado:\n{os.path.basename(file_path)}\n\nO PDF original será substituído pelo arquivo assinado.")
        sim_button = confirm.addButton("Sim", QMessageBox.YesRole)
        nao_button = confirm.addButton("Não", QMessageBox.NoRole)
        confirm.setDefaultButton(nao_button)
        
        confirm.exec()
        
        if confirm.clickedButton() == sim_button:
            db = Database()
            success = db.upload_signed_report(laudo_id, file_path)
            error_detail = ""
            if hasattr(db, 'get_last_upload_error'):
                try:
                    error_detail = db.get_last_upload_error() or ""
                except Exception:
                    error_detail = ""
            db.close_connection()
            
            if success:
                widget: AlertWindow = AlertWindow(f"PDF assinado enviado com sucesso para o laudo {laudo_id}!")
                widget.exec()
            else:
                details_msg = f"\n\nDetalhes:\n{error_detail}" if error_detail else ""
                widget: AlertWindow = AlertWindow(f"Erro ao enviar PDF assinado.{details_msg}")
                widget.exec()
    
    def remove_report(self) -> None:
        """Remove um laudo do sistema"""
        selected_items: list[QTableWidgetItem] = self.report_table.selectedIndexes()
        
        if len(selected_items) == 0:
            widget: AlertWindow = AlertWindow("Você deve selecionar um laudo para remover.")
            widget.exec()
            return
        
        # Verifica se selecionou apenas uma linha
        for data in selected_items:
            if data.row() != selected_items[0].row():
                widget: AlertWindow = AlertWindow("Você só pode remover um laudo por vez.")
                widget.exec()
                return
        
        row: int = selected_items[0].row()
        id_text = self.report_table.item(row, 0).text()
        requester_text = self.report_table.item(row, 1).text()
        
        try:
            laudo_id: int = int(id_text)
        except (TypeError, ValueError):
            widget: AlertWindow = AlertWindow("Laudo selecionado sem ID válido.")
            widget.exec()
            return
        
        # Confirmação dupla para operação destrutiva
        from PySide6.QtWidgets import QMessageBox
        confirm = QMessageBox()
        confirm.setIcon(QMessageBox.Warning)
        confirm.setWindowTitle("Confirmar Remoção")
        confirm.setText(f"ATENÇÃO: Deseja realmente REMOVER o laudo ID {laudo_id}?")
        confirm.setInformativeText(f"Solicitante: {requester_text}\n\n⚠️ Esta ação é IRREVERSÍVEL!\nO laudo será deletado permanentemente do banco de dados e não poderá ser recuperado.")
        sim_button = confirm.addButton("Sim", QMessageBox.YesRole)
        nao_button = confirm.addButton("Não", QMessageBox.NoRole)
        confirm.setDefaultButton(nao_button)
        
        confirm.exec()
        
        if confirm.clickedButton() == sim_button:
            db = Database()
            success = db.delete_report(laudo_id)
            db.close_connection()
            
            if success:
                widget: AlertWindow = AlertWindow(f"Laudo {laudo_id} removido com sucesso!")
                widget.exec()
                self.refresh_table()  # Atualiza a tabela
            else:
                widget: AlertWindow = AlertWindow(f"Erro ao remover laudo {laudo_id}.\n\nVerifique o console para mais detalhes.")
                widget.exec()
    
    def publish_report(self) -> None:
        """Publica um laudo (marca como revisado e disponível para o produtor)"""
        selected_items: list[QTableWidgetItem] = self.report_table.selectedIndexes()
        
        if len(selected_items) == 0:
            widget: AlertWindow = AlertWindow("Você deve selecionar um laudo para publicar.")
            widget.exec()
            return
        
        # Verifica se selecionou apenas uma linha
        for data in selected_items:
            if data.row() != selected_items[0].row():
                widget: AlertWindow = AlertWindow("Você só pode publicar um laudo por vez.")
                widget.exec()
                return
        
        row: int = selected_items[0].row()
        id_text = self.report_table.item(row, 0).text()
        
        try:
            laudo_id: int = int(id_text)
        except (TypeError, ValueError):
            widget: AlertWindow = AlertWindow("Laudo selecionado sem ID válido.")
            widget.exec()
            return
        
        # Confirmação
        from PySide6.QtWidgets import QMessageBox
        confirm = QMessageBox()
        confirm.setIcon(QMessageBox.Question)
        confirm.setWindowTitle("Confirmar Publicação")
        confirm.setText(f"Deseja publicar o laudo ID {laudo_id}?")
        confirm.setInformativeText("Após a publicação, o laudo ficará visível para o produtor no site.\n\nCertifique-se de que o laudo foi revisado e assinado.")
        sim_button = confirm.addButton("Sim", QMessageBox.YesRole)
        nao_button = confirm.addButton("Não", QMessageBox.NoRole)
        confirm.setDefaultButton(nao_button)
        
        confirm.exec()
        
        if confirm.clickedButton() == sim_button:
            db = Database()
            result = db.publish_report(laudo_id)
            db.close_connection()
            
            if result['success']:
                widget: AlertWindow = AlertWindow(f"✓ Laudo {laudo_id} publicado com sucesso!\n\nO produtor agora pode visualizá-lo no site.")
                widget.exec()
                self.refresh_table()  # Atualiza a tabela
            elif result.get('already_published'):
                # Laudo já estava publicado
                widget: AlertWindow = AlertWindow(
                    f"⚠ Laudo {laudo_id} já foi publicado\n\n"
                    f"Este laudo já estava publicado anteriormente e já está visível para o produtor no site.\n\n"
                    f"Não é necessário publicá-lo novamente."
                )
                widget.exec()
            else:
                # Outro tipo de erro
                error_msg = result.get('message', 'Erro desconhecido')
                widget: AlertWindow = AlertWindow(
                    f"✗ Erro ao publicar laudo {laudo_id}\n\n"
                    f"Detalhes: {error_msg}\n\n"
                    f"Verifique sua conexão com o servidor e tente novamente."
                )
                widget.exec()