<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\Transaction;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class TransactionController extends Controller
{
    //
    public function all(Request $request)
    {
        $id = $request->input("id");
        $limit = $request->input("limit", 6);
        $status = $request->input("status");

        if ($id) {
            $transaction = Transaction::with(["item.product"])->find($id);
            if ($transaction) {
                return ResponseFormatter::success(
                    $transaction,
                    "Data Transaksi Berhasil Diambil"
                );
            } else {
                return ResponseFormatter::error(
                    null,
                    "Data Transaksi Tidak Ada",
                    404
                );
            }
        }
        $transaction = Transaction::with(["item.product"])->where("user_id", Auth::user()->id);
        if ($status) {
            $transaction->where("status", $status);
        }
        return ResponseFormatter::success([
            $transaction->paginate($limit),
            "Data list transaksi berhasil diambil"
        ]);
    }
}
